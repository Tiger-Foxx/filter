#ifndef FOX_DEEP_TCP_REASSEMBLER_HPP
#define FOX_DEEP_TCP_REASSEMBLER_HPP

/**
 * TcpReassembler Simplex - Architecture "Bare Metal" inspirée de Suricata
 * 
 * OPTIMISATION CRITIQUE (Fichier Expert 08/12/25) :
 * =================================================
 * 
 * Mode SIMPLEX : On ne scanne QUE le trafic Client→Serveur
 * 
 * Gains :
 * - CPU : Trafic retour (Server→Client) traité en O(1)
 * - RAM : Division par 2 (un seul stream par session)
 * - Robustesse : Focus sur la reconstruction de l'attaque
 * 
 * Fonctionnement :
 * 1. Au SYN, on mémorise l'IP source comme "client_ip"
 * 2. Paquets venant du client_ip → SCAN Hyperscan
 * 3. Paquets venant du serveur → touch() seulement (maintien timeout)
 */

#include "tcp_stream.hpp"
#include "hs_matcher.hpp"
#include "../core/flow_key.hpp"
#include "../core/types.hpp"
#include "../config.hpp"
#include "../utils/logger.hpp"
#include <unordered_map>
#include <memory>

namespace fox::deep {

    // Session Unidirectionnelle (Optimisée pour Client -> Serveur)
    struct TcpSession {
        uint32_t client_ip = 0;           // L'IP qu'on surveille (Source de l'attaque)
        std::unique_ptr<TcpStream> stream; // Un seul stream !
        bool malicious = false;            // Verdict caché
    };

    class TcpReassembler {
    public:
        explicit TcpReassembler(HSMatcher* matcher) : _matcher(matcher) {
            _sessions.reserve(fox::config::MAX_CONCURRENT_FLOWS);
        }

        ~TcpReassembler() {
            for (auto& kv : _sessions) {
                if (kv.second.stream) {
                    _matcher->close_stream(kv.second.stream->get_hs_stream());
                }
            }
        }

        /**
         * Check O(1) : Est-ce un flux déjà condamné ?
         * Utilisé par Engine au "Niveau 0.5" pour bypass le FastPath.
         */
        TcpStream::State get_flow_verdict(const fox::core::FlowKey& key) const {
            auto it = _sessions.find(key);
            if (it != _sessions.end()) {
                if (it->second.malicious) {
                    return TcpStream::State::MALICIOUS;
                }
                return it->second.stream ? it->second.stream->get_state() 
                                          : TcpStream::State::ACTIVE;
            }
            return TcpStream::State::ACTIVE;
        }
        
        /**
         * Gestion du cycle de vie (FIN/RST) pour flux déjà condamnés.
         * N'effectue PAS de scan - sert uniquement à nettoyer la session.
         */
        void handle_lifecycle(const fox::core::FlowKey& key, 
                              bool is_fin, 
                              bool is_rst) {
            if (is_rst) {
                remove_session(key);
                return;
            }
            if (is_fin) {
                remove_session(key);
                return;
            }
            // Sinon, on ne fait rien - le flux reste marqué MALICIOUS
        }

        /**
         * Point d'entrée principal - Mode SIMPLEX
         * 
         * @param key Clé de flux canonique (bidirectionnelle)
         * @param src_ip IP source du paquet actuel (CRITIQUE pour savoir qui parle)
         * @param seq Numéro de séquence TCP
         * @param is_syn/is_fin/is_rst Flags TCP
         * @param payload Données du segment
         * @param rule Règle avec hs_id, atomic_ids, is_multi, is_or
         * 
         * @return true si le paquet doit être droppé
         */
        bool process_packet(const fox::core::FlowKey& key, 
                            uint32_t src_ip,
                            uint32_t seq, 
                            bool is_syn, 
                            bool is_fin, 
                            bool is_rst,
                            std::span<const uint8_t> payload,
                            const fox::core::RuleDefinition& rule) {

            // Maintenance légère (tous les 2048 paquets)
            if ((++_ops & 0x7FF) == 0) cleanup();

            // RST = Reset brutal
            if (is_rst) {
                fox::log::reassembly("RST received, removing stream");
                remove_session(key);
                return false;
            }

            auto it = _sessions.find(key);

            // Nouveau flux
            if (it == _sessions.end()) {
                // On n'accepte de créer un état QUE sur un SYN
                if (!is_syn) return false;

                if (_sessions.size() >= fox::config::MAX_CONCURRENT_FLOWS) {
                    force_cleanup();
                    if (_sessions.size() >= fox::config::MAX_CONCURRENT_FLOWS) {
                        fox::log::reassembly("Max flows reached, dropping");
                        return false;
                    }
                }

                hs_stream_t* hs_ctx = _matcher->open_stream();
                if (!hs_ctx) {
                    fox::log::reassembly("Failed to open HS stream");
                    return false;
                }

                TcpSession session;
                session.client_ip = src_ip; // Verrouiller cette IP comme "Client"
                
                // +1 si SYN pour consommer le numéro de séquence virtuel
                uint32_t init_seq = seq + 1;
                session.stream = std::make_unique<TcpStream>(init_seq, hs_ctx);
                
                it = _sessions.emplace(key, std::move(session)).first;
                fox::log::reassembly("New stream created");
            }

            TcpSession& session = it->second;

            // Fast Drop si déjà condamné
            if (session.malicious) {
                if (is_fin) {
                    fox::log::reassembly("FIN on DROPPED stream, cleaning up");
                    remove_session(key);
                }
                return true; // Maintenir le DROP
            }

            // =========================================================
            // DISCRIMINATION DIRECTIONNELLE (L'Optimisation Simplex)
            // =========================================================
            if (src_ip != session.client_ip) {
                // TRAFIC RETOUR (Serveur -> Client)
                // On garde la session en vie (évite timeout), mais ZÉRO scan
                session.stream->touch();
                
                if (is_fin) remove_session(key);
                return false; // PASS immédiat
            }

            // =========================================================
            // TRAFIC MONTANT (Client -> Serveur) -> INSPECTION
            // =========================================================
            
            // Ajustement seq pour le SYN initial déjà consommé
            uint32_t effective_seq = is_syn ? seq + 1 : seq;
            
            // Réassemblage
            std::vector<uint8_t> data = session.stream->process_segment(effective_seq, payload);
            
            if constexpr (fox::config::DEBUG_MODE) {
                if (!data.empty()) {
                    fox::log::reassembly("Reassembled data ready for scan", data.size());
                    fox::log::payload_ascii(data.data(), data.size(), 200);
                }
            }

            // Scan s'il y a des données ordonnées
            bool matched = false;
            if (!data.empty()) {
                // NOUVEAU: Utiliser scan_multi si règle multi-pattern
                if (rule.is_multi) {
                    matched = _matcher->scan_stream_multi(session.stream->get_hs_stream(), 
                                                          data, 
                                                          rule.atomic_ids, 
                                                          rule.is_or);
                } else {
                    matched = _matcher->scan_stream(session.stream->get_hs_stream(), data, rule.hs_id);
                }
                fox::log::hs_match(rule.hs_id, matched);
                
                if (matched) {
                    session.stream->set_dropped();
                    session.malicious = true;
                    fox::log::reassembly("Stream marked as DROPPED");
                }
            }

            // Fin de connexion
            if (is_fin) {
                fox::log::reassembly("FIN received, removing stream");
                remove_session(key);
            }

            return matched;
        }

    private:
        HSMatcher* _matcher;
        std::unordered_map<fox::core::FlowKey, TcpSession, fox::core::FlowKeyHash> _sessions;
        uint64_t _ops = 0;
        static constexpr uint64_t CLEANUP_INTERVAL = 10000;

        void remove_session(const fox::core::FlowKey& key) {
            auto it = _sessions.find(key);
            if (it != _sessions.end()) {
                if (it->second.stream) {
                    _matcher->close_stream(it->second.stream->get_hs_stream());
                }
                _sessions.erase(it);
            }
        }

        void cleanup() {
            size_t removed = 0;
            auto it = _sessions.begin();
            while (it != _sessions.end()) {
                if (it->second.stream && it->second.stream->is_expired(fox::config::FLOW_TIMEOUT_SEC)) {
                    _matcher->close_stream(it->second.stream->get_hs_stream());
                    it = _sessions.erase(it);
                    removed++;
                } else {
                    ++it;
                }
            }
            if (removed > 0) {
                fox::log::reassembly(("Cleaned " + std::to_string(removed) + " expired streams").c_str());
            }
        }

        void force_cleanup() {
            cleanup();
        }
    };
}

#endif // FOX_DEEP_TCP_REASSEMBLER_HPP
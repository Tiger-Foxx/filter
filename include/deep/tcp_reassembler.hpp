#ifndef FOX_DEEP_TCP_REASSEMBLER_HPP
#define FOX_DEEP_TCP_REASSEMBLER_HPP

/**
 * TcpReassembler - Architecture Mode BLOCK Hyperscan
 * 
 * CHANGEMENT ARCHITECTURAL CRITIQUE - Février 2026
 * ================================================
 * 
 * AVANT (Mode STREAM - LENT) :
 * - Un hs_stream_t par connexion TCP (open_stream/scan_stream/close_stream)
 * - Accumulation : 1000 connexions = 1000 streams Hyperscan
 * - Timeout 60s + cleanup insuffisant = effondrement progressif (1500 → 200 req/sec)
 * 
 * MAINTENANT (Mode BLOCK - RAPIDE comme Suricata) :
 * - TcpStream gère UNIQUEMENT le réassemblage TCP
 * - Une fois les données ordonnées, un SEUL appel hs_scan() en mode BLOCK
 * - Pas de stream Hyperscan par connexion
 * - Performance constante quel que soit le nombre de connexions
 * 
 * Mode SIMPLEX maintenu : On ne scanne QUE le trafic Client→Serveur
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
        std::unique_ptr<TcpStream> stream; // Réassemblage TCP uniquement
        bool malicious = false;            // Verdict caché
    };

    class TcpReassembler {
    public:
        explicit TcpReassembler(HSMatcher* matcher) : _matcher(matcher) {
            _sessions.reserve(fox::config::MAX_CONCURRENT_FLOWS);
        }

        ~TcpReassembler() = default; // Plus de cleanup Hyperscan nécessaire

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
            if (is_rst || is_fin) {
                remove_session(key);
            }
        }

        /**
         * NOUVELLE ARCHITECTURE - Point d'entrée principal
         * 
         * Réassemble le paquet TCP et scanne en MODE BLOCK.
         * 
         * @param key Clé de flux canonique (bidirectionnelle)
         * @param src_ip IP source du paquet actuel (CRITIQUE pour savoir qui parle)
         * @param seq Numéro de séquence TCP
         * @param is_syn/is_fin/is_rst Flags TCP
         * @param payload Données du segment
         * 
         * @return true si le paquet doit être droppé (match trouvé ou flux déjà condamné)
         */
        bool process_packet(const fox::core::FlowKey& key, 
                            uint32_t src_ip,
                            uint32_t seq, 
                            bool is_syn, 
                            bool is_fin, 
                            bool is_rst,
                            std::span<const uint8_t> payload) {

            // Maintenance légère (tous les 2048 paquets)
            if ((++_ops & 0x7FF) == 0) cleanup();

            // RST = Reset brutal
            if (is_rst) {
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
                        return false;
                    }
                }

                TcpSession session;
                session.client_ip = src_ip;
                
                // +1 si SYN pour consommer le numéro de séquence virtuel
                uint32_t init_seq = seq + 1;
                session.stream = std::make_unique<TcpStream>(init_seq);
                
                it = _sessions.emplace(key, std::move(session)).first;
            }

            TcpSession& session = it->second;

            // Fast Drop si déjà condamné
            if (session.malicious) {
                if (is_fin) {
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
            
            // Réassemblage (retourne données ordonnées via zero-copy)
            auto data = session.stream->push_segment_zerocopy(effective_seq, payload);
            
            // Scan s'il y a des données ordonnées
            bool matched = false;
            if (!data.empty()) {
                // MODE BLOCK : Un seul appel hs_scan(), pas de stream
                matched = _matcher->scan(data.data(), data.size());
                
                if (matched) {
                    session.stream->set_dropped();
                    session.malicious = true;
                }
            }

            // Fin de connexion
            if (is_fin) {
                remove_session(key);
            }

            return matched;
        }

        /**
         * Alternative : Réassemble et collecte tous les IDs matchés
         * (Pour l'Engine qui gère la logique multi-règles)
         */
        bool reassemble_and_scan(const fox::core::FlowKey& key, 
                                  uint32_t src_ip,
                                  uint32_t seq, 
                                  bool is_syn, 
                                  bool is_fin, 
                                  bool is_rst,
                                  std::span<const uint8_t> payload,
                                  std::vector<uint32_t>& matched_ids) {

            matched_ids.clear();

            if ((++_ops & 0x7FF) == 0) cleanup();

            if (is_rst) {
                remove_session(key);
                return false;
            }

            auto it = _sessions.find(key);

            if (it == _sessions.end()) {
                if (!is_syn) return false;

                if (_sessions.size() >= fox::config::MAX_CONCURRENT_FLOWS) {
                    force_cleanup();
                    if (_sessions.size() >= fox::config::MAX_CONCURRENT_FLOWS) {
                        return false;
                    }
                }

                TcpSession session;
                session.client_ip = src_ip;
                session.stream = std::make_unique<TcpStream>(seq + 1);
                
                it = _sessions.emplace(key, std::move(session)).first;
            }

            TcpSession& session = it->second;

            if (session.malicious) {
                if (is_fin) remove_session(key);
                return true;
            }

            if (src_ip != session.client_ip) {
                session.stream->touch();
                if (is_fin) remove_session(key);
                return false;
            }

            uint32_t effective_seq = is_syn ? seq + 1 : seq;
            auto data = session.stream->push_segment_zerocopy(effective_seq, payload);
            
            if (!data.empty()) {
                // MODE BLOCK avec collecte de tous les IDs
                _matcher->scan_collect_all(data.data(), data.size(), matched_ids);
            }

            if (is_fin) {
                remove_session(key);
            }

            return false; // Le DROP sera déterminé par l'Engine
        }

        /**
         * Marquer un flux comme malveillant (appelé par l'Engine après vérification des règles)
         */
        void mark_malicious(const fox::core::FlowKey& key) {
            auto it = _sessions.find(key);
            if (it != _sessions.end()) {
                it->second.malicious = true;
                if (it->second.stream) {
                    it->second.stream->set_dropped();
                }
            }
        }

        size_t session_count() const { return _sessions.size(); }

    private:
        HSMatcher* _matcher;
        std::unordered_map<fox::core::FlowKey, TcpSession, fox::core::FlowKeyHash> _sessions;
        uint64_t _ops = 0;

        void remove_session(const fox::core::FlowKey& key) {
            _sessions.erase(key);
        }

        void cleanup() {
            auto it = _sessions.begin();
            while (it != _sessions.end()) {
                if (it->second.stream && it->second.stream->is_expired(fox::config::FLOW_TIMEOUT_SEC)) {
                    it = _sessions.erase(it);
                } else {
                    ++it;
                }
            }
        }

        void force_cleanup() {
            cleanup();
        }
    };
}

#endif // FOX_DEEP_TCP_REASSEMBLER_HPP
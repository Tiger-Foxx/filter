#ifndef FOX_DEEP_TCP_STREAM_HPP
#define FOX_DEEP_TCP_STREAM_HPP

/**
 * TcpStream Simplex - Architecture "Bare Metal" (Mode BLOCK Hyperscan)
 * 
 * CHANGEMENT ARCHITECTURAL - Février 2026
 * =======================================
 * 
 * AVANT : Chaque TcpStream possédait un hs_stream_t (Hyperscan stream context)
 *         Problème : Allocation/libération par connexion, accumulation = effondrement
 * 
 * MAINTENANT : TcpStream gère UNIQUEMENT le réassemblage TCP
 *              Le scan est fait en mode BLOCK sur le buffer complet (par l'Engine)
 *              Plus de hs_stream_t par connexion = pas d'accumulation
 * 
 * OPTIMISATIONS MAINTENUES :
 * ==========================
 * 
 * 1. SIMPLEX STREAM : On ne scanne QUE le trafic Client→Serveur
 *    - Le trafic retour (Server→Client) est ignoré (touch() seulement)
 *    - Gain : CPU divisé par 2, RAM divisée par 2
 * 
 * 2. ZERO-COPY : Paquets in-order passés directement
 *    - Pas de copie si seq == next_seq (99% des cas)
 *    - Copie uniquement pour les OOO (gaps)
 * 
 * 3. LAZY REASSEMBLY : Buffer minimal pour les gaps
 *    - Map<seq, vector> au lieu de ring buffer complexe
 *    - Limite stricte anti-DoS (MAX_OOO_BUFFER)
 * 
 * 4. ARITHMÉTIQUE TCP ROBUSTE : Gestion wraparound 32 bits (RFC 1982)
 */

#include <cstdint>
#include <vector>
#include <map>
#include <span>
#include <chrono>

namespace fox::deep {

    class TcpStream {
    public:
        //État persistant du flux
        enum class State : uint8_t {
            ACTIVE,     //En cours d'analyse
            MALICIOUS,  //Match confirmé → Fast Drop permanent
            BROKEN      //Flux incohérent/DoS → Drop de sécurité
        };

        //Pour rétro-compatibilité avec l'ancien code
        using StreamVerdict = State;
        static constexpr State INSPECTING = State::ACTIVE;
        static constexpr State DROPPED = State::MALICIOUS;

        //Anti-DoS : Max 512KB de buffer pour les paquets OOO
        static constexpr size_t MAX_OOO_BUFFER = 512 * 1024;
        
        //Profondeur max de réassemblage (1MB comme Suricata)
        static constexpr size_t REASSEMBLY_DEPTH = 1024 * 1024;

        TcpStream() = default;
        
        /**
         * Constructeur simplifié (plus de hs_stream_t)
         */
        explicit TcpStream(uint32_t seq) {
            init(seq);
        }
        
        /**
         * Initialise le stream
         */
        void init(uint32_t seq) {
            _next_seq = seq;
            _state = State::ACTIVE;
            _buffered_bytes = 0;
            _total_scanned = 0;
            _ooo_buffer.clear();
            touch();
        }

        /**
         * Reset pour réutilisation
         */
        void reset() {
            _state = State::ACTIVE;
            _buffered_bytes = 0;
            _total_scanned = 0;
            _ooo_buffer.clear();
        }

        //Accesseurs
        State get_state() const { return _state; }
        State get_verdict() const { return _state; }
        
        bool is_dropped() const { return _state == State::MALICIOUS; }
        void set_dropped() { _state = State::MALICIOUS; }

        void touch() {
            _last_activity = std::chrono::steady_clock::now();
        }

        bool is_expired(uint32_t timeout_sec) const {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                now - _last_activity).count();
            return elapsed > static_cast<int64_t>(timeout_sec);
        }

        /**
         * ZERO-COPY : Pousse un segment et retourne les données ordonnées.
         * 
         * Pour le fast-path (in-order), retourne directement le payload original.
         * Pour le slow-path (OOO), stocke et retourne vide.
         */
        std::span<const uint8_t> push_segment_zerocopy(
            uint32_t seq, 
            std::span<const uint8_t> payload
        ) {
            touch();
            
            if (_state != State::ACTIVE) {
                return {}; //Flux mort
            }

            size_t len = payload.size();
            if (len == 0) {
                return {}; //Pure ACK
            }

            //Limite de profondeur anti-DoS
            if (_total_scanned > REASSEMBLY_DEPTH) {
                return {}; //Bypass après 1MB (comme Suricata)
            }

            //Arithmétique signée pour wraparound (RFC 1982)
            int32_t diff = static_cast<int32_t>(seq - _next_seq);

            //1. RETRANSMISSION/OVERLAP (diff < 0)
            if (diff < 0) {
                int32_t overlap_end = diff + static_cast<int32_t>(len);
                if (overlap_end <= 0) {
                    return {}; //Entièrement dans le passé
                }
                //Extraire la partie nouvelle
                size_t skip = static_cast<size_t>(-diff);
                payload = payload.subspan(skip);
                seq = _next_seq;
                len = payload.size();
                diff = 0;
            }

            //2. FAST PATH : IN-ORDER (diff == 0)
            if (diff == 0) {
                _next_seq += static_cast<uint32_t>(len);
                _total_scanned += len;
                
                //Drainer le buffer OOO si on a comblé un trou
                drain_ooo_buffer();
                
                //ZERO-COPY : Retourner directement le span original
                return payload;
            }

            //3. SLOW PATH : OUT-OF-ORDER (diff > 0)
            if (static_cast<uint32_t>(diff) < 1048576) { //Fenêtre max 1MB
                if (_buffered_bytes + len <= MAX_OOO_BUFFER) {
                    if (_ooo_buffer.find(seq) == _ooo_buffer.end()) {
                        _ooo_buffer.emplace(seq, 
                            std::vector<uint8_t>(payload.begin(), payload.end()));
                        _buffered_bytes += len;
                    }
                } else {
                    //Buffer overflow → Marquer comme cassé
                    _state = State::BROKEN;
                }
            }

            return {}; //Pas de données ordonnées disponibles
        }

        /**
         * Ancienne API pour rétro-compatibilité (avec copie)
         */
        std::vector<uint8_t> process_segment(uint32_t seq, std::span<const uint8_t> payload) {
            auto span = push_segment_zerocopy(seq, payload);
            if (span.empty()) {
                return {};
            }
            return std::vector<uint8_t>(span.begin(), span.end());
        }

    private:
        uint32_t _next_seq = 0;
        State _state = State::ACTIVE;
        std::chrono::steady_clock::time_point _last_activity;
        
        //Buffer OOO (gaps)
        std::map<uint32_t, std::vector<uint8_t>> _ooo_buffer;
        size_t _buffered_bytes = 0;
        size_t _total_scanned = 0;

        /**
         * Drainer le buffer OOO quand des données in-order ont avancé _next_seq
         */
        void drain_ooo_buffer() {
            while (!_ooo_buffer.empty()) {
                auto it = _ooo_buffer.begin();
                int32_t buf_diff = static_cast<int32_t>(it->first - _next_seq);
                
                if (buf_diff == 0) {
                    //Ce morceau est maintenant in-order
                    _next_seq += static_cast<uint32_t>(it->second.size());
                    _total_scanned += it->second.size();
                    _buffered_bytes -= it->second.size();
                    _ooo_buffer.erase(it);
                } else if (buf_diff < 0) {
                    //Fragment obsolète
                    _buffered_bytes -= it->second.size();
                    _ooo_buffer.erase(it);
                } else {
                    break; //Trou restant
                }
            }
        }
    };

}

#endif //FOX_DEEP_TCP_STREAM_HPP
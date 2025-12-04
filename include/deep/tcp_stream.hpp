#ifndef FOX_DEEP_TCP_STREAM_HPP
#define FOX_DEEP_TCP_STREAM_HPP

#include <cstdint>
#include <vector>
#include <map>
#include <span>
#include <chrono>
#include <hs/hs.h>

namespace fox::deep {

    /**
     * Gère l'état d'un flux TCP (Séquence, Trous, Stream Hyperscan, Verdict persistant).
     */
    class TcpStream {
    public:
        /**
         * État persistant du flux - CORRECTION CRITIQUE pour le "Paradoxe du DROP"
         * 
         * Problème : Un paquet TCP matche un pattern → DROP, mais les paquets suivants
         * de la même connexion ne sont pas droppés car l'état n'est pas persisté.
         * 
         * Solution : Marquer le flux comme DROPPED dès le premier match.
         * Tous les paquets suivants du même flux seront rejetés immédiatement.
         */
        enum class StreamVerdict {
            INSPECTING, // En cours d'analyse (défaut)
            DROPPED     // Match confirmé, flux condamné définitivement
        };

        // seq est le numéro de séquence initial (ISN + 1)
        TcpStream(uint32_t seq, hs_stream_t* hs_ctx) 
            : _next_seq(seq), _hs_stream(hs_ctx), _verdict(StreamVerdict::INSPECTING) {
            touch();
        }

        // Met à jour le timestamp de dernière activité
        void touch() {
            _last_activity = std::chrono::steady_clock::now();
        }

        // Vérifie si le flux a expiré
        bool is_expired(uint32_t timeout_sec) const {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - _last_activity).count();
            return elapsed > timeout_sec;
        }

        hs_stream_t* get_hs_stream() const { return _hs_stream; }

        // --- Gestion de l'état persistant ---
        StreamVerdict get_verdict() const { return _verdict; }
        void set_dropped() { _verdict = StreamVerdict::DROPPED; }
        bool is_dropped() const { return _verdict == StreamVerdict::DROPPED; }

        /**
         * Insère un segment. Retourne les données remises dans l'ordre.
         * Retourne un vecteur vide si doublon ou trou.
         * 
         * GESTION DU WRAPAROUND TCP:
         * Les numéros de séquence sont sur 32 bits et wrap à 0 après 4GB.
         * On utilise une arithmétique signée pour comparer correctement.
         */
        std::vector<uint8_t> process_segment(uint32_t seq, std::span<const uint8_t> payload) {
            touch(); // Mise à jour de l'activité
            
            // Calcul de la différence avec arithmétique signée pour gérer le wraparound
            // Si diff < 0 : seq est "avant" _next_seq (retransmission/doublon)
            // Si diff > 0 : seq est "après" _next_seq (out-of-order)
            // Si diff == 0 : segment attendu
            int32_t diff = static_cast<int32_t>(seq - _next_seq);
            
            // 1. Déjà vu (Doublon ou ancien) - segment complètement dans le passé
            if (diff < 0) {
                // Vérifier si le segment chevauche partiellement les données attendues
                int32_t overlap_end = diff + static_cast<int32_t>(payload.size());
                if (overlap_end <= 0) {
                    return {}; // Entièrement dans le passé, ignorer
                }
                // Segment partiellement nouveau : extraire la partie utile
                size_t skip = static_cast<size_t>(-diff);
                if (skip < payload.size()) {
                    payload = payload.subspan(skip);
                    seq = _next_seq;
                    diff = 0;
                } else {
                    return {};
                }
            }

            // 2. En avance (Out of Order)
            if (diff > 0) {
                // Protection mémoire simple (Max 100 fragments)
                // On utilise aussi une fenêtre max de 1MB pour éviter les abus
                if (_ooo_buffer.size() < 100 && diff < 1048576) {
                    _ooo_buffer[seq] = std::vector<uint8_t>(payload.begin(), payload.end());
                }
                return {};
            }

            // 3. En ordre (diff == 0, seq == _next_seq)
            std::vector<uint8_t> ordered_data(payload.begin(), payload.end());
            _next_seq += static_cast<uint32_t>(payload.size());

            // Vérification des paquets en attente pour combler les trous
            auto it = _ooo_buffer.begin();
            while (it != _ooo_buffer.end()) {
                int32_t buf_diff = static_cast<int32_t>(it->first - _next_seq);
                
                if (buf_diff == 0) {
                    // On colle le morceau suivant
                    ordered_data.insert(ordered_data.end(), it->second.begin(), it->second.end());
                    _next_seq += static_cast<uint32_t>(it->second.size());
                    it = _ooo_buffer.erase(it);
                } else if (buf_diff < 0) {
                    // Vieux fragment devenu inutile (déjà couvert)
                    it = _ooo_buffer.erase(it);
                } else {
                    // Prochain fragment est encore trop loin (nouveau trou)
                    break;
                }
            }

            return ordered_data;
        }

    private:
        uint32_t _next_seq;
        hs_stream_t* _hs_stream;
        StreamVerdict _verdict;
        std::map<uint32_t, std::vector<uint8_t>> _ooo_buffer;
        std::chrono::steady_clock::time_point _last_activity;
    };
}

#endif // FOX_DEEP_TCP_STREAM_HPP
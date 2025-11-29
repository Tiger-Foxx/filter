#ifndef FOX_DEEP_TCP_STREAM_HPP
#define FOX_DEEP_TCP_STREAM_HPP

#include <cstdint>
#include <vector>
#include <map>
#include <span>
#include <hs/hs.h>

namespace fox::deep {

    /**
     * Gère l'état d'un flux TCP (Séquence, Trous, Stream Hyperscan).
     */
    class TcpStream {
    public:
        // seq est le numéro de séquence initial (ISN + 1)
        TcpStream(uint32_t seq, hs_stream_t* hs_ctx) 
            : _next_seq(seq), _hs_stream(hs_ctx) {}

        hs_stream_t* get_hs_stream() const { return _hs_stream; }

        /**
         * Insère un segment. Retourne les données remises dans l'ordre.
         * Retourne un vecteur vide si doublon ou trou.
         */
        std::vector<uint8_t> process_segment(uint32_t seq, std::span<const uint8_t> payload) {
            // 1. Déjà vu (Doublon ou ancien)
            if (seq < _next_seq && (seq + payload.size()) <= _next_seq) {
                return {}; 
            }

            // 2. En avance (Out of Order)
            if (seq > _next_seq) {
                // Protection mémoire simple (Max 100 fragments)
                if (_ooo_buffer.size() < 100) {
                    _ooo_buffer[seq] = std::vector<uint8_t>(payload.begin(), payload.end());
                }
                return {};
            }

            // 3. En ordre (seq == _next_seq) ou chevauchement partiel gérable
            // Note: Pour cette PoC, on suppose un alignement parfait ou on prend le bloc complet.
            std::vector<uint8_t> ordered_data(payload.begin(), payload.end());
            _next_seq += payload.size();

            // Vérification des paquets en attente pour combler les trous
            auto it = _ooo_buffer.begin();
            while (it != _ooo_buffer.end()) {
                if (it->first == _next_seq) {
                    // On colle le morceau suivant
                    ordered_data.insert(ordered_data.end(), it->second.begin(), it->second.end());
                    _next_seq += it->second.size();
                    it = _ooo_buffer.erase(it);
                } else if (it->first < _next_seq) {
                    // Vieux fragment devenu inutile
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
        std::map<uint32_t, std::vector<uint8_t>> _ooo_buffer;
    };
}

#endif // FOX_DEEP_TCP_STREAM_HPP
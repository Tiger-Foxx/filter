#ifndef FOX_DEEP_TCP_STREAM_FAST_HPP
#define FOX_DEEP_TCP_STREAM_FAST_HPP

#include <cstdint>
#include <cstring>
#include <array>
#include <span>
#include <chrono>
#include <algorithm>
#include <hs/hs.h>
#include "../config.hpp"

namespace fox::deep {

    /**
     * Structure légère pour un segment OOO (Out-of-Order).
     * Pré-alloué dans un tableau fixe pour éviter les allocations dynamiques.
     */
    struct OOOSegment {
        uint32_t seq = 0;
        uint16_t len = 0;
        bool used = false;
        // Données inline (max 1500 bytes = MTU typique)
        alignas(64) uint8_t data[1500];
    };

    /**
     * TcpStreamFast - Version haute performance du flux TCP.
     * 
     * OPTIMISATIONS:
     * 1. Ring Buffer pré-alloué au lieu de std::vector
     * 2. Segments OOO en tableau fixe (pas de std::map)
     * 3. Scan incrémental Hyperscan (pas d'accumulation)
     * 4. Cache-line aligned pour éviter le false sharing
     * 5. Fonctions inline pour le hot path
     */
    class alignas(64) TcpStreamFast {
    public:
        static constexpr size_t RING_BUFFER_SIZE = 65536; // 64KB ring buffer
        static constexpr size_t MAX_OOO_SEGMENTS = 32;    // Max 32 segments OOO
        static constexpr int32_t MAX_WINDOW = 1 << 20;    // Fenêtre max 1MB

        TcpStreamFast() = default;

        // Initialisation (appelé depuis le pool)
        void init(uint32_t initial_seq, hs_stream_t* hs_ctx) noexcept {
            _next_seq = initial_seq;
            _hs_stream = hs_ctx;
            _ring_head = 0;
            _ring_tail = 0;
            _ooo_count = 0;
            _last_activity = std::chrono::steady_clock::now();
            _active = true;
            
            // Reset des segments OOO
            for (auto& seg : _ooo_segments) {
                seg.used = false;
            }
        }

        void reset() noexcept {
            _active = false;
            _hs_stream = nullptr;
        }

        [[nodiscard]] bool is_active() const noexcept { return _active; }
        [[nodiscard]] hs_stream_t* get_hs_stream() const noexcept { return _hs_stream; }

        void touch() noexcept {
            _last_activity = std::chrono::steady_clock::now();
        }

        [[nodiscard]] bool is_expired(uint32_t timeout_sec) const noexcept {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - _last_activity).count();
            return elapsed > static_cast<int64_t>(timeout_sec);
        }

        /**
         * Traite un segment TCP et retourne un pointeur vers les données ordonnées.
         * 
         * RETOUR:
         * - span vide si pas de données à scanner
         * - span vers le ring buffer si données prêtes
         * 
         * IMPORTANT: Le span retourné est valide jusqu'au prochain appel !
         */
        [[nodiscard]] std::span<const uint8_t> process_segment_fast(
            uint32_t seq, 
            std::span<const uint8_t> payload
        ) noexcept {
            if (payload.empty()) return {};
            
            touch();

            // Arithmétique signée pour wraparound
            const int32_t diff = static_cast<int32_t>(seq - _next_seq);

            // 1. Segment dans le passé (retransmission)
            if (diff < 0) {
                const int32_t overlap = diff + static_cast<int32_t>(payload.size());
                if (overlap <= 0) return {}; // Entièrement ancien
                
                // Partie chevauchante : on garde seulement le nouveau
                const size_t skip = static_cast<size_t>(-diff);
                payload = payload.subspan(skip);
                // seq devient _next_seq (on a skipé les anciens bytes)
            }
            // 2. Segment dans le futur (out-of-order)
            else if (diff > 0) {
                if (diff > MAX_WINDOW) return {}; // Trop loin, probablement invalide
                store_ooo_segment(seq, payload);
                return {};
            }

            // 3. Segment en ordre - écriture dans le ring buffer
            const size_t written = write_to_ring(payload);
            _next_seq += static_cast<uint32_t>(written);

            // 4. Essayer de coller les segments OOO
            drain_ooo_segments();

            // 5. Retourner les données disponibles pour scan
            return get_scannable_data();
        }

        /**
         * Récupère les données du ring buffer pour le scan.
         * Après le scan, appeler mark_scanned() pour libérer l'espace.
         */
        [[nodiscard]] std::span<const uint8_t> get_scannable_data() const noexcept {
            if (_ring_head == _ring_tail) return {};
            
            // Données contiguës disponibles
            if (_ring_head < _ring_tail) {
                return {_ring_buffer.data() + _ring_head, _ring_tail - _ring_head};
            } else {
                // Wrap-around: retourne la première partie (jusqu'à la fin du buffer)
                // Le caller devra appeler une deuxième fois pour la suite
                return {_ring_buffer.data() + _ring_head, RING_BUFFER_SIZE - _ring_head};
            }
        }

        void mark_scanned(size_t bytes) noexcept {
            _ring_head = (_ring_head + bytes) % RING_BUFFER_SIZE;
        }

        [[nodiscard]] size_t pending_bytes() const noexcept {
            if (_ring_tail >= _ring_head) {
                return _ring_tail - _ring_head;
            }
            return RING_BUFFER_SIZE - _ring_head + _ring_tail;
        }

    private:
        // --- Données chaudes (accédées fréquemment) - alignées cache ---
        alignas(64) uint32_t _next_seq = 0;
        hs_stream_t* _hs_stream = nullptr;
        size_t _ring_head = 0;  // Position de lecture
        size_t _ring_tail = 0;  // Position d'écriture
        uint8_t _ooo_count = 0;
        bool _active = false;
        
        std::chrono::steady_clock::time_point _last_activity;

        // --- Ring buffer pré-alloué ---
        alignas(64) std::array<uint8_t, RING_BUFFER_SIZE> _ring_buffer;
        
        // --- Segments OOO (tableau fixe) ---
        std::array<OOOSegment, MAX_OOO_SEGMENTS> _ooo_segments;

        size_t write_to_ring(std::span<const uint8_t> data) noexcept {
            const size_t available = RING_BUFFER_SIZE - pending_bytes() - 1;
            const size_t to_write = std::min(data.size(), available);
            
            if (to_write == 0) return 0;

            // Écriture potentiellement en deux parties (wrap-around)
            const size_t first_chunk = std::min(to_write, RING_BUFFER_SIZE - _ring_tail);
            std::memcpy(_ring_buffer.data() + _ring_tail, data.data(), first_chunk);
            
            if (first_chunk < to_write) {
                std::memcpy(_ring_buffer.data(), data.data() + first_chunk, to_write - first_chunk);
            }
            
            _ring_tail = (_ring_tail + to_write) % RING_BUFFER_SIZE;
            return to_write;
        }

        void store_ooo_segment(uint32_t seq, std::span<const uint8_t> payload) noexcept {
            if (_ooo_count >= MAX_OOO_SEGMENTS) return;
            if (payload.size() > sizeof(OOOSegment::data)) return;

            // Trouver un slot libre
            for (auto& seg : _ooo_segments) {
                if (!seg.used) {
                    seg.seq = seq;
                    seg.len = static_cast<uint16_t>(payload.size());
                    seg.used = true;
                    std::memcpy(seg.data, payload.data(), payload.size());
                    _ooo_count++;
                    return;
                }
            }
        }

        void drain_ooo_segments() noexcept {
            bool progress = true;
            while (progress && _ooo_count > 0) {
                progress = false;
                
                for (auto& seg : _ooo_segments) {
                    if (!seg.used) continue;
                    
                    const int32_t diff = static_cast<int32_t>(seg.seq - _next_seq);
                    
                    if (diff <= 0) {
                        // Ce segment est maintenant dans le passé ou exactement attendu
                        if (diff == 0) {
                            // Exactement le segment attendu
                            const size_t written = write_to_ring({seg.data, seg.len});
                            _next_seq += static_cast<uint32_t>(written);
                        }
                        // Dans tous les cas, libérer le slot
                        seg.used = false;
                        _ooo_count--;
                        progress = true;
                    }
                }
            }
        }
    };

} // namespace fox::deep

#endif // FOX_DEEP_TCP_STREAM_FAST_HPP

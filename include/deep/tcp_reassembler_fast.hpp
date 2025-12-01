#ifndef FOX_DEEP_TCP_REASSEMBLER_FAST_HPP
#define FOX_DEEP_TCP_REASSEMBLER_FAST_HPP

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <hs/hs.h>
#include "tcp_stream_fast.hpp"
#include "../core/flow_key.hpp"
#include "../core/verdict.hpp"
#include "../config.hpp"

namespace fox::deep {

    // Imports pour éviter les préfixes verbeux
    using fox::Verdict;
    using fox::core::FlowKey;

    /**
     * Structure pour l'entrée de la table de hash des flux.
     * Optimisée pour le cache (compacte).
     */
    struct FlowEntry {
        FlowKey key{};
        uint32_t stream_index = UINT32_MAX; // Index dans le pool de streams
        uint32_t hash = 0;
        bool active = false;
    };

    /**
     * TcpReassemblerFast - Gestionnaire haute performance des flux TCP.
     * 
     * OPTIMISATIONS:
     * 1. Pool de streams pré-alloué (pas de new/delete)
     * 2. Table de hash ouverte avec probing linéaire
     * 3. Freelist pour recyclage rapide des streams
     * 4. Scan incrémental Hyperscan
     * 5. Nettoyage lazy des flux expirés
     */
    class TcpReassemblerFast {
    public:
        static constexpr size_t MAX_FLOWS = 65536;          // Doit être puissance de 2
        static constexpr size_t HASH_TABLE_SIZE = MAX_FLOWS * 2; // Load factor 0.5
        static constexpr uint32_t INVALID_INDEX = UINT32_MAX;

        explicit TcpReassemblerFast(const HsMatcher& matcher) 
            : _matcher(&matcher) 
        {
            // Initialiser la freelist
            for (uint32_t i = 0; i < MAX_FLOWS; ++i) {
                _freelist[i] = i;
            }
            _freelist_head = 0;
            _freelist_count = MAX_FLOWS;
        }

        ~TcpReassemblerFast() {
            // Fermer tous les streams Hyperscan actifs
            for (auto& stream : _stream_pool) {
                if (stream.is_active() && stream.get_hs_stream()) {
                    hs_close_stream(stream.get_hs_stream(), nullptr, nullptr, nullptr);
                }
            }
        }

        // Non-copiable
        TcpReassemblerFast(const TcpReassemblerFast&) = delete;
        TcpReassemblerFast& operator=(const TcpReassemblerFast&) = delete;

        /**
         * Traite un paquet TCP.
         * 
         * Retourne:
         * - PASS si pas de match
         * - DROP si pattern malveillant détecté
         */
        [[nodiscard]] core::Verdict process_packet(
            const core::FlowKey& key,
            uint32_t tcp_seq,
            uint8_t tcp_flags,
            std::span<const uint8_t> payload
        ) noexcept {
            _packet_count++;

            // Nettoyage périodique (lazy)
            if ((_packet_count & 0xFFFF) == 0) { // Tous les 65536 paquets
                cleanup_expired_flows();
            }

            constexpr uint8_t SYN = 0x02;
            constexpr uint8_t FIN = 0x01;
            constexpr uint8_t RST = 0x04;

            // RST ou FIN: fermer le flux
            if (tcp_flags & (FIN | RST)) {
                close_flow(key);
                return core::Verdict::PASS;
            }

            // SYN: nouveau flux
            if (tcp_flags & SYN) {
                // Fermer l'ancien si existe
                close_flow(key);
                
                // Ouvrir un nouveau
                if (!open_flow(key, tcp_seq + 1)) {
                    return core::Verdict::PASS; // Pool plein, on laisse passer
                }
            }

            // Pas de payload = rien à inspecter
            if (payload.empty()) {
                return core::Verdict::PASS;
            }

            // Trouver le flux
            TcpStreamFast* stream = find_stream(key);
            if (!stream) {
                // Flux inconnu avec payload: créer un nouveau (mid-stream)
                if (!open_flow(key, tcp_seq)) {
                    return core::Verdict::PASS;
                }
                stream = find_stream(key);
                if (!stream) return core::Verdict::PASS;
            }

            // Réassembler et inspecter
            return reassemble_and_scan(stream, tcp_seq, payload);
        }

        // Statistiques
        [[nodiscard]] size_t active_flows() const noexcept {
            return MAX_FLOWS - _freelist_count;
        }

        [[nodiscard]] uint64_t total_packets() const noexcept {
            return _packet_count;
        }

    private:
        const HsMatcher* _matcher;
        uint64_t _packet_count = 0;

        // Pool de streams pré-alloué
        std::array<TcpStreamFast, MAX_FLOWS> _stream_pool;

        // Table de hash pour lookup rapide
        std::array<FlowEntry, HASH_TABLE_SIZE> _hash_table{};

        // Freelist pour allocation rapide
        std::array<uint32_t, MAX_FLOWS> _freelist{};
        uint32_t _freelist_head = 0;
        uint32_t _freelist_count = 0;

        // Scratch buffer pour le scan (évite allocation par paquet)
        alignas(64) std::array<uint8_t, 65536> _scan_buffer;

        // Hash function (FNV-1a rapide)
        [[nodiscard]] static uint32_t hash_flow_key(const core::FlowKey& key) noexcept {
            uint32_t hash = 2166136261u;
            const uint8_t* data = reinterpret_cast<const uint8_t*>(&key);
            for (size_t i = 0; i < sizeof(core::FlowKey); ++i) {
                hash ^= data[i];
                hash *= 16777619u;
            }
            return hash;
        }

        // Trouver un slot dans la table de hash
        [[nodiscard]] uint32_t find_slot(const core::FlowKey& key, uint32_t hash) const noexcept {
            uint32_t slot = hash & (HASH_TABLE_SIZE - 1);
            uint32_t probe = 0;
            
            while (_hash_table[slot].active) {
                if (_hash_table[slot].hash == hash && _hash_table[slot].key == key) {
                    return slot; // Trouvé
                }
                probe++;
                slot = (slot + probe) & (HASH_TABLE_SIZE - 1);
                if (probe >= HASH_TABLE_SIZE) break; // Table pleine (ne devrait pas arriver)
            }
            return slot;
        }

        TcpStreamFast* find_stream(const core::FlowKey& key) noexcept {
            const uint32_t hash = hash_flow_key(key);
            const uint32_t slot = find_slot(key, hash);
            
            if (_hash_table[slot].active && _hash_table[slot].key == key) {
                return &_stream_pool[_hash_table[slot].stream_index];
            }
            return nullptr;
        }

        bool open_flow(const core::FlowKey& key, uint32_t initial_seq) noexcept {
            // Vérifier si on a de la place
            if (_freelist_count == 0) {
                return false;
            }

            // Allouer un stream depuis la freelist
            uint32_t stream_idx = _freelist[_freelist_head];
            _freelist_head = (_freelist_head + 1) % MAX_FLOWS;
            _freelist_count--;

            // Ouvrir le stream Hyperscan
            hs_stream_t* hs_stream = nullptr;
            if (_matcher->get_database()) {
                if (hs_open_stream(_matcher->get_database(), 0, &hs_stream) != HS_SUCCESS) {
                    // Échec: remettre dans la freelist
                    _freelist_head = (_freelist_head - 1 + MAX_FLOWS) % MAX_FLOWS;
                    _freelist[_freelist_head] = stream_idx;
                    _freelist_count++;
                    return false;
                }
            }

            // Initialiser le stream
            _stream_pool[stream_idx].init(initial_seq, hs_stream);

            // Insérer dans la table de hash
            const uint32_t hash = hash_flow_key(key);
            uint32_t slot = find_slot(key, hash);
            
            // Si le slot est déjà pris par un autre flux, chercher un slot libre
            if (_hash_table[slot].active && _hash_table[slot].key != key) {
                // Linear probing pour trouver un slot vide
                uint32_t probe = 1;
                while (_hash_table[slot].active) {
                    slot = (slot + probe) & (HASH_TABLE_SIZE - 1);
                    probe++;
                    if (probe >= HASH_TABLE_SIZE) {
                        // Table pleine - ne devrait pas arriver avec notre load factor
                        _stream_pool[stream_idx].reset();
                        if (hs_stream) hs_close_stream(hs_stream, nullptr, nullptr, nullptr);
                        return false;
                    }
                }
            }

            _hash_table[slot] = {key, stream_idx, hash, true};
            return true;
        }

        void close_flow(const core::FlowKey& key) noexcept {
            const uint32_t hash = hash_flow_key(key);
            const uint32_t slot = find_slot(key, hash);
            
            if (!_hash_table[slot].active || _hash_table[slot].key != key) {
                return; // Pas trouvé
            }

            const uint32_t stream_idx = _hash_table[slot].stream_index;
            TcpStreamFast& stream = _stream_pool[stream_idx];

            // Fermer le stream Hyperscan
            if (stream.get_hs_stream()) {
                hs_close_stream(stream.get_hs_stream(), nullptr, nullptr, nullptr);
            }

            // Reset et remettre dans la freelist
            stream.reset();
            uint32_t freelist_tail = (_freelist_head + _freelist_count) % MAX_FLOWS;
            _freelist[freelist_tail] = stream_idx;
            _freelist_count++;

            // Marquer le slot comme libre
            _hash_table[slot].active = false;
        }

        [[nodiscard]] core::Verdict reassemble_and_scan(
            TcpStreamFast* stream, 
            uint32_t tcp_seq, 
            std::span<const uint8_t> payload
        ) noexcept {
            // Traiter le segment
            auto data_to_scan = stream->process_segment_fast(tcp_seq, payload);
            
            if (data_to_scan.empty()) {
                return core::Verdict::PASS;
            }

            // Scanner avec Hyperscan
            hs_stream_t* hs_stream = stream->get_hs_stream();
            if (!hs_stream) {
                stream->mark_scanned(data_to_scan.size());
                return core::Verdict::PASS;
            }

            bool matched = false;
            
            // Callback pour Hyperscan
            auto on_match = [](unsigned int /*id*/, 
                              unsigned long long /*from*/,
                              unsigned long long /*to*/, 
                              unsigned int /*flags*/, 
                              void* ctx) -> int {
                *static_cast<bool*>(ctx) = true;
                return 1; // Stop au premier match
            };

            // Scanner les données
            hs_error_t err = hs_scan_stream(
                hs_stream,
                reinterpret_cast<const char*>(data_to_scan.data()),
                static_cast<unsigned int>(data_to_scan.size()),
                0,
                _matcher->get_scratch(),
                on_match,
                &matched
            );

            // Marquer comme scanné
            stream->mark_scanned(data_to_scan.size());

            if (err != HS_SUCCESS && err != HS_SCAN_TERMINATED) {
                return core::Verdict::PASS; // Erreur Hyperscan, laisser passer
            }

            return matched ? core::Verdict::DROP : core::Verdict::PASS;
        }

        void cleanup_expired_flows() noexcept {
            constexpr uint32_t TIMEOUT_SEC = fox::config::FLOW_TIMEOUT_SEC;
            
            for (auto& entry : _hash_table) {
                if (entry.active) {
                    TcpStreamFast& stream = _stream_pool[entry.stream_index];
                    if (stream.is_expired(TIMEOUT_SEC)) {
                        close_flow(entry.key);
                    }
                }
            }
        }
    };

} // namespace fox::deep

#endif // FOX_DEEP_TCP_REASSEMBLER_FAST_HPP

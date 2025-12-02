#ifndef FOX_DEEP_TCP_REASSEMBLER_HPP
#define FOX_DEEP_TCP_REASSEMBLER_HPP

#include "tcp_stream.hpp"
#include "hs_matcher.hpp"
#include "../core/flow_key.hpp"
#include "../config.hpp"
#include "../utils/logger.hpp"
#include <unordered_map>
#include <memory>

namespace fox::deep {

    class TcpReassembler {
    public:
        explicit TcpReassembler(HSMatcher* matcher) : _matcher(matcher) {}

        /**
         * Point d'entrée principal pour un paquet TCP.
         * Gère la création/destruction de flux et délègue le scan.
         */
        bool process_packet(const fox::core::FlowKey& key, 
                            uint32_t seq, 
                            bool is_syn, 
                            bool is_fin, 
                            bool is_rst,
                            std::span<const uint8_t> payload,
                            uint32_t rule_hs_id) {

            // Cleanup périodique des flux expirés
            maybe_cleanup();

            // RST = Reset brutal
            if (is_rst) {
                fox::log::reassembly("RST received, removing stream");
                remove_stream(key);
                return false;
            }

            TcpStream* stream = nullptr;
            auto it = _streams.find(key);

            // Nouveau flux
            if (it == _streams.end()) {
                if (_streams.size() >= fox::config::MAX_CONCURRENT_FLOWS) {
                    force_cleanup();
                    if (_streams.size() >= fox::config::MAX_CONCURRENT_FLOWS) {
                        fox::log::reassembly("Max flows reached, dropping");
                        return false;
                    }
                }

                hs_stream_t* hs_ctx = _matcher->open_stream();
                if (!hs_ctx) {
                    fox::log::reassembly("Failed to open HS stream");
                    return false;
                }

                uint32_t init_seq = seq + (is_syn ? 1 : 0);
                auto ptr = std::make_unique<TcpStream>(init_seq, hs_ctx);
                stream = ptr.get();
                _streams[key] = std::move(ptr);
                fox::log::reassembly("New stream created", payload.size());
            } else {
                stream = it->second.get();
            }

            // Réassemblage
            std::vector<uint8_t> data = stream->process_segment(seq, payload);
            
            if constexpr (fox::config::DEBUG_MODE) {
                if (!data.empty()) {
                    fox::log::reassembly("Reassembled data ready for scan", data.size());
                    fox::log::payload_ascii(data.data(), data.size(), 200);
                }
            }

            // Scan s'il y a des données ordonnées
            bool matched = false;
            if (!data.empty()) {
                matched = _matcher->scan_stream(stream->get_hs_stream(), data, rule_hs_id);
                fox::log::hs_match(rule_hs_id, matched);
            }

            // Fin de connexion
            if (is_fin) {
                fox::log::reassembly("FIN received, removing stream");
                remove_stream(key);
            }

            return matched;
        }

    private:
        HSMatcher* _matcher;
        std::unordered_map<fox::core::FlowKey, std::unique_ptr<TcpStream>, fox::core::FlowKeyHash> _streams;
        uint64_t _packet_counter = 0;
        static constexpr uint64_t CLEANUP_INTERVAL = 10000;

        void remove_stream(const fox::core::FlowKey& key) {
            auto it = _streams.find(key);
            if (it != _streams.end()) {
                _matcher->close_stream(it->second->get_hs_stream());
                _streams.erase(it);
            }
        }

        void maybe_cleanup() {
            _packet_counter++;
            if (_packet_counter % CLEANUP_INTERVAL == 0) {
                force_cleanup();
            }
        }

        void force_cleanup() {
            size_t removed = 0;
            auto it = _streams.begin();
            while (it != _streams.end()) {
                if (it->second->is_expired(fox::config::FLOW_TIMEOUT_SEC)) {
                    _matcher->close_stream(it->second->get_hs_stream());
                    it = _streams.erase(it);
                    removed++;
                } else {
                    ++it;
                }
            }
            if (removed > 0) {
                fox::log::reassembly(("Cleaned " + std::to_string(removed) + " expired streams").c_str());
            }
        }
    };
}

#endif // FOX_DEEP_TCP_REASSEMBLER_HPP
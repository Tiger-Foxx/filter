#ifndef FOX_DEEP_TCP_REASSEMBLER_HPP
#define FOX_DEEP_TCP_REASSEMBLER_HPP

#include "tcp_stream.hpp"
#include "hs_matcher.hpp"
#include "../core/flow_key.hpp"
#include "../config.hpp"
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

            // RST = Reset brutal
            if (is_rst) {
                remove_stream(key);
                return false;
            }

            TcpStream* stream = nullptr;
            auto it = _streams.find(key);

            // Nouveau flux
            if (it == _streams.end()) {
                // On n'accepte la création que sur SYN (ou on force si on veut être permissif)
                // Pour la PoC : Création auto si place dispo
                if (_streams.size() >= fox::config::MAX_CONCURRENT_FLOWS) return false;

                hs_stream_t* hs_ctx = _matcher->open_stream();
                if (!hs_ctx) return false;

                // ISN + 1 si SYN
                uint32_t init_seq = seq + (is_syn ? 1 : 0);
                auto ptr = std::make_unique<TcpStream>(init_seq, hs_ctx);
                stream = ptr.get();
                _streams[key] = std::move(ptr);
            } else {
                stream = it->second.get();
            }

            // Réassemblage
            std::vector<uint8_t> data = stream->process_segment(seq, payload);

            // Scan s'il y a des données ordonnées
            bool matched = false;
            if (!data.empty()) {
                matched = _matcher->scan_stream(stream->get_hs_stream(), data, rule_hs_id);
            }

            // Fin de connexion
            if (is_fin) {
                // Dans un vrai TCP stack on attendrait ACK du FIN, mais ici on nettoie direct
                remove_stream(key);
            }

            return matched;
        }

    private:
        HSMatcher* _matcher;
        std::unordered_map<fox::core::FlowKey, std::unique_ptr<TcpStream>, fox::core::FlowKeyHash> _streams;

        void remove_stream(const fox::core::FlowKey& key) {
            auto it = _streams.find(key);
            if (it != _streams.end()) {
                _matcher->close_stream(it->second->get_hs_stream());
                _streams.erase(it);
            }
        }
    };
}

#endif // FOX_DEEP_TCP_REASSEMBLER_HPP
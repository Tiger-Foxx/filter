#ifndef FOX_CORE_ENGINE_HPP
#define FOX_CORE_ENGINE_HPP

#include <memory>
#include "../fastpath/ip_radix.hpp"
#include "../fastpath/port_map.hpp"
#include "../deep/hs_matcher.hpp"
#include "../deep/tcp_reassembler.hpp"
#include "packet.hpp"
#include "verdict.hpp"
#include "types.hpp"
#include "flow_key.hpp"

namespace fox::core {

    class Engine {
    public:
        static Engine& instance() {
            static Engine instance;
            return instance;
        }

        void init(fox::fastpath::IPRadixTrie<RuleDefinition>* trie, fox::deep::HSMatcher* matcher) {
            _trie = trie;
            _matcher = matcher;
            // Initialisation du module de réassemblage
            _reassembler = std::make_unique<fox::deep::TcpReassembler>(matcher);
        }

        Verdict process(const Packet& pkt) {
            if (!pkt.is_valid()) return Verdict::ACCEPT;

            // 1. FASTPATH (IP / Port / Proto)
            // Note: pkt.src_ip() retourne déjà en Host Order (ntohl appliqué dans Packet)
            const RuleDefinition* rule = _trie->lookup_host_order(pkt.src_ip());
            
            if (!rule) return Verdict::ACCEPT;
            
            // Validation IP Destination (OPTIMISÉE - comparaison binaire)
            if (!match_ip_binary(pkt.dst_ip(), rule->optimized_dst_ips)) return Verdict::ACCEPT;
            
            // Validation Ports (Source ET Destination)
            if (!fox::fastpath::PortMatcher::match(pkt.dst_port(), *rule)) return Verdict::ACCEPT;
            if (!fox::fastpath::PortMatcher::match_src(pkt.src_port(), *rule)) return Verdict::ACCEPT;
            
            // Validation Protocole
            if (rule->get_proto_id() != 0 && rule->get_proto_id() != pkt.protocol()) return Verdict::ACCEPT;

            // 2. Verdict immédiat si pas d'inspection
            if (rule->hs_id == 0) return rule->get_verdict();

            // 3. DEEP PATH (Inspection Stateful)
            if (pkt.protocol() == IPPROTO_TCP) {
                FlowKey key { pkt.src_ip(), pkt.dst_ip(), pkt.src_port(), pkt.dst_port() };
                
                bool match = _reassembler->process_packet(
                    key, 
                    pkt.tcp_seq(), 
                    pkt.is_syn(), 
                    pkt.is_fin(), 
                    pkt.is_rst(), 
                    pkt.payload(), 
                    rule->hs_id
                );

                if (match) return rule->get_verdict();
                
            } else {
                // UDP / ICMP : Scan direct
                if (!pkt.payload().empty()) {
                    if (_matcher->scan_block(pkt.payload(), rule->hs_id)) {
                        return rule->get_verdict();
                    }
                }
            }

            return Verdict::ACCEPT;
        }

    private:
        Engine() = default;
        fox::fastpath::IPRadixTrie<RuleDefinition>* _trie = nullptr;
        fox::deep::HSMatcher* _matcher = nullptr;
        std::unique_ptr<fox::deep::TcpReassembler> _reassembler;

        /**
         * Vérification binaire ultra-rapide des IPs.
         * Plus de string parsing ! Juste des opérations bitwise.
         * Complexité: O(N) où N = nombre de CIDRs (généralement 1-3 après optimisation Python)
         */
        static bool match_ip_binary(uint32_t ip_host, const std::vector<Cidr>& cidrs) {
            if (cidrs.empty()) return true; // ANY
            
            for (const auto& cidr : cidrs) {
                // Cas ANY: mask=0 -> (ip & 0) == 0 -> toujours vrai
                // Cas normal: (IP & Mask) == Network
                if ((ip_host & cidr.mask) == cidr.network) return true;
            }
            return false;
        }
    };
}

#endif // FOX_CORE_ENGINE_HPP
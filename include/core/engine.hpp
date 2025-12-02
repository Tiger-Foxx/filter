#ifndef FOX_CORE_ENGINE_HPP
#define FOX_CORE_ENGINE_HPP

#include <memory>
#include <atomic>
#include "../fastpath/ip_radix.hpp"
#include "../fastpath/port_map.hpp"
#include "../deep/hs_matcher.hpp"
#include "../deep/tcp_reassembler.hpp"
#include "../utils/logger.hpp"
#include "../config.hpp"
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
            _reassembler = std::make_unique<fox::deep::TcpReassembler>(matcher);
            _packet_count = 0;
            fox::log::info("Engine initialized with DEBUG_MODE=" + std::string(fox::config::DEBUG_MODE ? "ON" : "OFF"));
        }

        Verdict process(const Packet& pkt) {
            _packet_count++;
            bool verbose = fox::config::DEBUG_MODE && 
                           (_packet_count <= fox::config::DEBUG_FIRST_N_PACKETS || 
                            fox::config::DEBUG_FIRST_N_PACKETS == 0);

            if (!pkt.is_valid()) {
                if (verbose) fox::log::debug("Invalid packet, ACCEPT");
                return Verdict::ACCEPT;
            }

            if (verbose) {
                fox::log::packet(pkt.src_ip(), pkt.dst_ip(), pkt.src_port(), pkt.dst_port(),
                                pkt.protocol(), pkt.payload().size());
                if (!pkt.payload().empty()) {
                    fox::log::payload_ascii(pkt.payload().data(), pkt.payload().size(), 200);
                }
            }

            // 1. FASTPATH (IP / Port / Proto)
            const RuleDefinition* rule = _trie->lookup_host_order(pkt.src_ip());
            
            if (!rule) {
                if (verbose) fox::log::debug("No rule matched src_ip in Radix Trie -> ACCEPT");
                return Verdict::ACCEPT;
            }
            
            if (verbose) {
                fox::log::debug("Radix Trie matched rule id=" + std::to_string(rule->id) + 
                               " hs_id=" + std::to_string(rule->hs_id) +
                               " action=" + rule->action);
            }
            
            // Validation IP Destination
            if (!match_ip_binary(pkt.dst_ip(), rule->optimized_dst_ips)) {
                if (verbose) fox::log::debug("Dst IP mismatch -> ACCEPT");
                return Verdict::ACCEPT;
            }
            
            // Validation Ports
            if (!fox::fastpath::PortMatcher::match(pkt.dst_port(), *rule)) {
                if (verbose) fox::log::debug("Dst Port mismatch -> ACCEPT");
                return Verdict::ACCEPT;
            }
            if (!fox::fastpath::PortMatcher::match_src(pkt.src_port(), *rule)) {
                if (verbose) fox::log::debug("Src Port mismatch -> ACCEPT");
                return Verdict::ACCEPT;
            }
            
            // Validation Protocole
            if (rule->get_proto_id() != 0 && rule->get_proto_id() != pkt.protocol()) {
                if (verbose) fox::log::debug("Protocol mismatch -> ACCEPT");
                return Verdict::ACCEPT;
            }

            if (verbose) fox::log::debug("L3/L4 filters PASSED, checking L7...");

            // 2. Verdict immédiat si pas d'inspection L7
            if (rule->hs_id == 0) {
                if (verbose) fox::log::verdict("NO_L7_CHECK", rule->id, 0);
                return rule->get_verdict();
            }

            // 3. DEEP PATH (Inspection L7)
            bool matched = false;
            
            if (pkt.protocol() == IPPROTO_TCP) {
                if (verbose) fox::log::debug("TCP packet -> Reassembler");
                
                FlowKey key { pkt.src_ip(), pkt.dst_ip(), pkt.src_port(), pkt.dst_port() };
                
                matched = _reassembler->process_packet(
                    key, 
                    pkt.tcp_seq(), 
                    pkt.is_syn(), 
                    pkt.is_fin(), 
                    pkt.is_rst(), 
                    pkt.payload(), 
                    rule->hs_id
                );
                
            } else {
                // UDP / ICMP : Scan direct
                if (!pkt.payload().empty()) {
                    if (verbose) fox::log::debug("UDP/ICMP direct scan, hs_id=" + std::to_string(rule->hs_id));
                    matched = _matcher->scan_block(pkt.payload(), rule->hs_id);
                }
            }

            if (matched) {
                fox::log::verdict("MATCH->DROP", rule->id, rule->hs_id);
                return rule->get_verdict();
            }
            
            if (verbose) fox::log::debug("No L7 match -> ACCEPT");
            return Verdict::ACCEPT;
        }

    private:
        Engine() = default;
        fox::fastpath::IPRadixTrie<RuleDefinition>* _trie = nullptr;
        fox::deep::HSMatcher* _matcher = nullptr;
        std::unique_ptr<fox::deep::TcpReassembler> _reassembler;
        std::atomic<uint64_t> _packet_count{0};

        static bool match_ip_binary(uint32_t ip_host, const std::vector<Cidr>& cidrs) {
            if (cidrs.empty()) return true;
            
            for (const auto& cidr : cidrs) {
                if ((ip_host & cidr.mask) == cidr.network) return true;
            }
            return false;
        }
    };
}

#endif // FOX_CORE_ENGINE_HPP
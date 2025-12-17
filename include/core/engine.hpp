#ifndef FOX_CORE_ENGINE_HPP
#define FOX_CORE_ENGINE_HPP

#include <memory>
#include <atomic>
#include "../fastpath/rule_index.hpp"
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

        void init(fox::fastpath::CompositeRuleIndex<RuleDefinition>* index, fox::deep::HSMatcher* matcher) {
            _index = index;
            _matcher = matcher;
            _reassembler = std::make_unique<fox::deep::TcpReassembler>(matcher);
            _packet_count = 0;
            fox::log::info("Engine initialized (Composite Index + Stateful TCP)");
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

            // =========================================================================
            // NIVEAU 0.5 : BYPASS POUR FLUX TCP DÉJÀ CONDAMNÉS
            // =========================================================================
            FlowKey canonical_key;
            
            if (pkt.protocol() == IPPROTO_TCP) {
                canonical_key = FlowKey(pkt.src_ip(), pkt.dst_ip(), pkt.src_port(), pkt.dst_port());
                
                auto verdict = _reassembler->get_flow_verdict(canonical_key);
                if (verdict == fox::deep::TcpStream::State::MALICIOUS) {
                    if (verbose) fox::log::debug("Flow already DROPPED -> maintaining DROP");
                    _reassembler->handle_lifecycle(canonical_key, pkt.is_fin(), pkt.is_rst());
                    return Verdict::DROP;
                }
            }

            // =========================================================================
            // NIVEAU 1 : FASTPATH - INDEX COMPOSITE (IP + Port) en O(1)
            // =========================================================================
            // NOUVEAU: Lookup par (IP_src, Port_dst) directement
            // Retourne UNIQUEMENT les règles qui matchent cette combinaison
            auto candidate_rules = _index->lookup(pkt.src_ip(), pkt.dst_port());
            
            if (candidate_rules.empty()) {
                if (verbose) fox::log::debug("No rule matched (IP+Port) -> ACCEPT");
                return Verdict::ACCEPT;
            }
            
            if (verbose) {
                fox::log::debug("Composite Index found " + std::to_string(candidate_rules.size()) + " matching rules");
            }

            // Itérer sur les règles candidates (beaucoup moins qu'avant!)
            for (const RuleDefinition* rule : candidate_rules) {
                if (verbose) {
                    fox::log::debug("Checking rule id=" + std::to_string(rule->id) + 
                                   " hs_id=" + std::to_string(rule->hs_id));
                }
                
                // Validation IP Destination
                if (!match_ip_binary(pkt.dst_ip(), rule->optimized_dst_ips)) {
                    if (verbose) fox::log::debug("  -> Dst IP mismatch, skip");
                    continue;
                }
                
                // Validation Port Source (si spécifié)
                if (!fox::fastpath::PortMatcher::match_src(pkt.src_port(), *rule)) {
                    if (verbose) fox::log::debug("  -> Src Port mismatch, skip");
                    continue;
                }
                
                // Validation Protocole
                if (rule->get_proto_id() != 0 && rule->get_proto_id() != pkt.protocol()) {
                    if (verbose) fox::log::debug("  -> Protocol mismatch, skip");
                    continue;
                }

                if (verbose) fox::log::debug("  -> L3/L4 PASSED, checking L7...");

                // =================================================================
                // NIVEAU 2 : DEEP PATH (Inspection L7)
                // =================================================================
                if (rule->hs_id == 0) {
                    if (verbose) fox::log::verdict("NO_L7_CHECK", rule->id, 0);
                    return rule->get_verdict();
                }

                bool matched = false;
                
                if (pkt.protocol() == IPPROTO_TCP) {
                    matched = _reassembler->process_packet(
                        canonical_key, 
                        pkt.src_ip(),
                        pkt.tcp_seq(), 
                        pkt.is_syn(), 
                        pkt.is_fin(), 
                        pkt.is_rst(), 
                        pkt.payload(), 
                        *rule
                    );
                } else {
                    if (!pkt.payload().empty()) {
                        if (rule->is_multi) {
                            matched = _matcher->scan_block_multi(pkt.payload(), rule->atomic_ids, rule->is_or);
                        } else {
                            matched = _matcher->scan_block(pkt.payload(), rule->hs_id);
                        }
                    }
                }

                if (matched) {
                    fox::log::verdict("MATCH->DROP", rule->id, rule->hs_id);
                    return rule->get_verdict();
                }
            }
            
            if (verbose) fox::log::debug("No rule fully matched -> ACCEPT");
            return Verdict::ACCEPT;
        }

    private:
        Engine() = default;
        fox::fastpath::CompositeRuleIndex<RuleDefinition>* _index = nullptr;
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
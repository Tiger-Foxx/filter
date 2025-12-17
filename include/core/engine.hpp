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
            fox::log::info("Engine initialized (Stateful TCP + Canonical FlowKey)");
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
            // NIVEAU 0.5 : BYPASS POUR FLUX TCP DÉJÀ CONDAMNÉS (CORRECTION CRITIQUE)
            // =========================================================================
            // Problème résolu : "Paradoxe du DROP" - les paquets suivants d'une connexion
            // TCP matchée passaient car l'état n'était pas persisté.
            // 
            // Solution : Utiliser une clé canonique (bidirectionnelle) et vérifier
            // en O(1) si le flux est déjà marqué DROPPED avant tout autre traitement.
            // =========================================================================
            
            FlowKey canonical_key; // Défaut = (0,0,0,0)
            
            if (pkt.protocol() == IPPROTO_TCP) {
                // Clé canonique : même clé pour client→server et server→client
                canonical_key = FlowKey(pkt.src_ip(), pkt.dst_ip(), pkt.src_port(), pkt.dst_port());
                
                // Vérification O(1) de l'état connu du flux
                auto verdict = _reassembler->get_flow_verdict(canonical_key);
                if (verdict == fox::deep::TcpStream::State::MALICIOUS) {
                    if (verbose) fox::log::debug("Flow already DROPPED -> maintaining DROP");
                    
                    // Gérer uniquement le cycle de vie (FIN/RST) sans scan
                    _reassembler->handle_lifecycle(canonical_key, pkt.is_fin(), pkt.is_rst());
                    return Verdict::DROP;
                }
            }
            // =========================================================================

            // =========================================================================
            // NIVEAU 1 : FASTPATH (IP / Port / Proto)
            // =========================================================================
            // MODIFIÉ: Récupérer TOUTES les règles candidates (même IP, ports différents)
            auto candidate_rules = _trie->lookup_all_host_order(pkt.src_ip());
            
            if (candidate_rules.empty()) {
                if (verbose) fox::log::debug("No rule matched src_ip in Radix Trie -> ACCEPT");
                return Verdict::ACCEPT;
            }
            
            if (verbose) {
                fox::log::debug("Radix Trie found " + std::to_string(candidate_rules.size()) + " candidate rules");
            }
            
            // Itérer sur chaque règle candidate et vérifier les filtres L3/L4
            for (const RuleDefinition* rule : candidate_rules) {
                if (verbose) {
                    fox::log::debug("Checking rule id=" + std::to_string(rule->id) + 
                                   " hs_id=" + std::to_string(rule->hs_id) +
                                   " action=" + rule->action);
                }
                
                // Validation IP Destination
                if (!match_ip_binary(pkt.dst_ip(), rule->optimized_dst_ips)) {
                    if (verbose) fox::log::debug("  -> Dst IP mismatch, skip");
                    continue;
                }
                
                // Validation Ports
                if (!fox::fastpath::PortMatcher::match(pkt.dst_port(), *rule)) {
                    if (verbose) fox::log::debug("  -> Dst Port mismatch, skip");
                    continue;
                }
                if (!fox::fastpath::PortMatcher::match_src(pkt.src_port(), *rule)) {
                    if (verbose) fox::log::debug("  -> Src Port mismatch, skip");
                    continue;
                }
                
                // Validation Protocole
                if (rule->get_proto_id() != 0 && rule->get_proto_id() != pkt.protocol()) {
                    if (verbose) fox::log::debug("  -> Protocol mismatch, skip");
                    continue;
                }

                if (verbose) fox::log::debug("  -> L3/L4 filters PASSED, checking L7...");

                // =================================================================
                // NIVEAU 2 : DEEP PATH (Inspection L7)
                // =================================================================
                
                // Verdict immédiat si pas d'inspection L7 requise
                if (rule->hs_id == 0) {
                    if (verbose) fox::log::verdict("NO_L7_CHECK", rule->id, 0);
                    return rule->get_verdict();
                }

                bool matched = false;
                
                if (pkt.protocol() == IPPROTO_TCP) {
                    if (verbose) fox::log::debug("TCP packet -> Reassembler (Simplex mode)");
                    
                    // Utiliser la clé canonique déjà calculée + IP source pour Simplex
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
                    // UDP / ICMP : Scan direct (pas de réassemblage)
                    if (!pkt.payload().empty()) {
                        if (rule->is_multi) {
                            if (verbose) fox::log::debug("UDP/ICMP multi-pattern scan (" + 
                                                        std::string(rule->is_or ? "OR" : "AND") + ")");
                            matched = _matcher->scan_block_multi(pkt.payload(), rule->atomic_ids, rule->is_or);
                        } else {
                            if (verbose) fox::log::debug("UDP/ICMP direct scan, hs_id=" + std::to_string(rule->hs_id));
                            matched = _matcher->scan_block(pkt.payload(), rule->hs_id);
                        }
                    }
                }

                if (matched) {
                    fox::log::verdict("MATCH->DROP", rule->id, rule->hs_id);
                    return rule->get_verdict();
                }
            }
            
            // Aucune règle n'a matché complètement
            if (verbose) fox::log::debug("No rule fully matched -> ACCEPT");
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
#ifndef FOX_CORE_ENGINE_FAST_HPP
#define FOX_CORE_ENGINE_FAST_HPP

#include <memory>
#include <cstdint>
#include "../fastpath/ip_radix.hpp"
#include "../fastpath/port_map.hpp"
#include "../deep/hs_matcher.hpp"
#include "../deep/tcp_reassembler_fast.hpp"
#include "packet.hpp"
#include "verdict.hpp"
#include "types.hpp"
#include "flow_key.hpp"

namespace fox::core {

    /**
     * EngineFast - Version haute performance du moteur de filtrage.
     * 
     * OPTIMISATIONS:
     * 1. Inline agressif des fonctions critiques
     * 2. Branch prediction hints (likely/unlikely)
     * 3. Réassemblage TCP sans allocation
     * 4. Cache-line alignment des structures
     * 5. Réduction des indirections de pointeurs
     */
    class EngineFast {
    public:
        static EngineFast& instance() {
            static EngineFast inst;
            return inst;
        }

        void init(fox::fastpath::IPRadixTrie<RuleDefinition>* trie, fox::deep::HSMatcher* matcher) {
            _trie = trie;
            _matcher = matcher;
            _reassembler = std::make_unique<fox::deep::TcpReassemblerFast>(*matcher);
        }

        /**
         * Pipeline de traitement optimisé.
         * 
         * ARCHITECTURE:
         * 1. FastPath: IP Source (Radix Trie O(32))
         * 2. FastPath: IP Dest + Ports + Proto (comparaisons inline)
         * 3. DeepPath: Scan Hyperscan si nécessaire
         */
        [[nodiscard]] __attribute__((hot)) 
        Verdict process(const Packet& pkt) noexcept {
            // --- VALIDATION RAPIDE ---
            if (__builtin_expect(!pkt.is_valid(), 0)) {
                return Verdict::ACCEPT;
            }

            // --- FASTPATH: LOOKUP IP SOURCE ---
            const RuleDefinition* rule = _trie->lookup_host_order(pkt.src_ip());
            
            if (__builtin_expect(rule == nullptr, 1)) { // Cas commun: pas de règle
                return Verdict::ACCEPT;
            }
            
            // --- FASTPATH: VALIDATIONS INLINE ---
            
            // IP Destination
            if (!match_ip_fast(pkt.dst_ip(), rule->optimized_dst_ips)) {
                return Verdict::ACCEPT;
            }
            
            // Ports (destination puis source)
            if (!fox::fastpath::PortMatcher::match(pkt.dst_port(), *rule)) {
                return Verdict::ACCEPT;
            }
            if (!fox::fastpath::PortMatcher::match_src(pkt.src_port(), *rule)) {
                return Verdict::ACCEPT;
            }
            
            // Protocole (0 = ANY)
            const uint8_t rule_proto = rule->get_proto_id();
            if (rule_proto != 0 && rule_proto != pkt.protocol()) {
                return Verdict::ACCEPT;
            }

            // --- VERDICT IMMÉDIAT SI PAS D'INSPECTION ---
            if (rule->hs_id == 0) {
                return rule->get_verdict();
            }

            // --- DEEP PATH ---
            return process_deep(pkt, rule);
        }

        // Statistiques
        [[nodiscard]] uint64_t packets_processed() const noexcept {
            return _reassembler ? _reassembler->total_packets() : 0;
        }

        [[nodiscard]] size_t active_tcp_flows() const noexcept {
            return _reassembler ? _reassembler->active_flows() : 0;
        }

    private:
        EngineFast() = default;
        
        fox::fastpath::IPRadixTrie<RuleDefinition>* _trie = nullptr;
        fox::deep::HSMatcher* _matcher = nullptr;
        std::unique_ptr<fox::deep::TcpReassemblerFast> _reassembler;

        /**
         * Match IP avec vecteur de CIDRs - version optimisée.
         * ANY (vide) = match tout.
         */
        [[nodiscard]] static inline bool match_ip_fast(
            uint32_t ip_host, 
            const std::vector<Cidr>& cidrs
        ) noexcept {
            if (__builtin_expect(cidrs.empty(), 0)) { // ANY est rare
                return true;
            }
            
            // Déroulement manuel pour 1-2 CIDRs (cas courant après fusion)
            const size_t n = cidrs.size();
            if (n == 1) {
                return (ip_host & cidrs[0].mask) == cidrs[0].network;
            }
            if (n == 2) {
                return ((ip_host & cidrs[0].mask) == cidrs[0].network) ||
                       ((ip_host & cidrs[1].mask) == cidrs[1].network);
            }
            
            // Cas général
            for (const auto& cidr : cidrs) {
                if ((ip_host & cidr.mask) == cidr.network) {
                    return true;
                }
            }
            return false;
        }

        /**
         * Traitement DeepPath séparé pour éviter l'inlining excessif.
         */
        [[nodiscard]] __attribute__((noinline))
        Verdict process_deep(const Packet& pkt, const RuleDefinition* rule) noexcept {
            const uint8_t proto = pkt.protocol();

            // TCP: Réassemblage stateful
            if (proto == IPPROTO_TCP) {
                return process_tcp(pkt, rule);
            }
            
            // UDP/ICMP: Scan direct
            return process_udp_icmp(pkt, rule);
        }

        [[nodiscard]] Verdict process_tcp(const Packet& pkt, const RuleDefinition* rule) noexcept {
            // Construire la clé de flux
            FlowKey key{
                pkt.src_ip(), 
                pkt.dst_ip(), 
                pkt.src_port(), 
                pkt.dst_port()
            };

            // Extraire les flags TCP
            uint8_t tcp_flags = 0;
            if (pkt.is_syn()) tcp_flags |= 0x02;
            if (pkt.is_fin()) tcp_flags |= 0x01;
            if (pkt.is_rst()) tcp_flags |= 0x04;

            // Déléguer au reassembler haute performance
            Verdict v = _reassembler->process_packet(
                key,
                pkt.tcp_seq(),
                tcp_flags,
                pkt.payload()
            );

            // Si le reassembler a trouvé un match, appliquer le verdict de la règle
            if (v == Verdict::DROP) {
                return rule->get_verdict();
            }

            return Verdict::ACCEPT;
        }

        [[nodiscard]] Verdict process_udp_icmp(const Packet& pkt, const RuleDefinition* rule) noexcept {
            auto payload = pkt.payload();
            
            if (__builtin_expect(payload.empty(), 0)) {
                return Verdict::ACCEPT;
            }

            // Scan direct avec Hyperscan
            if (_matcher->scan_block(payload, rule->hs_id)) {
                return rule->get_verdict();
            }

            return Verdict::ACCEPT;
        }
    };

} // namespace fox::core

#endif // FOX_CORE_ENGINE_FAST_HPP

#ifndef FOX_FASTPATH_RULE_INDEX_HPP
#define FOX_FASTPATH_RULE_INDEX_HPP

/**
 * RuleIndex - Composite IP + Port index for O(1) lookup
 * 
 * PROBLEM SOLVED:
 * ================
 * The previous Radix Trie returned ALL rules with src_ip=any (e.g. 214 rules!)
 * because they all matched 0.0.0.0/0 at the root of the Trie.
 * Result: Linear O(N) scan of all rules = WORSE than Snort!
 * 
 * SOLUTION:
 * =========
 * Two-level index:
 *   1. Radix Trie on Source IP (as before)
 *   2. Hash Map on Destination Port (NEW)
 * 
 * Complexity: O(32) + O(1) = O(1) constant
 * 
 * STRUCTURE:
 * ==========
 * Source IP → {
 *     port 80   → [rule1, rule2]
 *     port 443  → [rule3]
 *     port ANY  → [rule4, rule5]  // Rules with dst_port = any
 * }
 */

#include <cstdint>
#include <vector>
#include <unordered_map>
#include <memory>
#include <string>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "../core/types.hpp"

namespace fox::fastpath {

    //Port spécial pour les règles qui matchent "any" port
    static constexpr uint32_t PORT_ANY = 0xFFFFFFFF;

    /**
     * Rule index by destination port.
     * Enables O(1) lookup after IP filtering.
     */
    template <typename T>
    class PortIndex {
    public:
        /**
         * Adds a rule to the index.
         * If the rule has specific ports, index by each port.
         * If the rule has port=any, index under PORT_ANY.
         */
        void add_rule(T* rule) {
            if (rule->dst_ports.empty()) {
                // Port = any -> accessible via PORT_ANY
                any_port_rules.push_back(rule);
            } else {
                // Index by each port/range
                for (const auto& range : rule->dst_ports) {
                    // For wide ranges (e.g. 0-65535), put in any_port
                    if (range.start == 0 && range.end == 65535) {
                        any_port_rules.push_back(rule);
                    } else if (range.end - range.start > 100) {
                        // Range too wide to index individually
                        // Put in a list of ranges to verify
                        wide_range_rules.push_back(rule);
                    } else {
                        // Small range: index each port individually
                        for (uint32_t p = range.start; p <= range.end; ++p) {
                            port_map[p].push_back(rule);
                        }
                    }
                }
            }
        }

        /**
         * Retrieves rules matching a given port.
         * Complexity: O(1) for lookup + O(k) for any/wide rules
         */
        std::vector<const T*> get_rules(uint16_t port) const {
            std::vector<const T*> result;
            
            // 1. Rules with this specific port
            auto it = port_map.find(port);
            if (it != port_map.end()) {
                for (T* r : it->second) {
                    result.push_back(r);
                }
            }
            
            // 2. Rules with port = any
            for (T* r : any_port_rules) {
                result.push_back(r);
            }
            
            // 3. Rules with wide ranges (verification required)
            for (T* r : wide_range_rules) {
                for (const auto& range : r->dst_ports) {
                    if (port >= range.start && port <= range.end) {
                        result.push_back(r);
                        break;
                    }
                }
            }
            
            return result;
        }

    private:
        std::unordered_map<uint32_t, std::vector<T*>> port_map;  // port → rules
        std::vector<T*> any_port_rules;   // Rules with port = any (0-65535)
        std::vector<T*> wide_range_rules; // Rules with wide ranges to verify
    };

    /**
     * Radix Trie node with integrated port index.
     */
    template <typename T>
    struct IndexedTrieNode {
        std::unique_ptr<IndexedTrieNode> left;
        std::unique_ptr<IndexedTrieNode> right;
        PortIndex<T> port_index;  // Port index for this IP prefix

        bool has_rules() const { return true; } // Simplified
    };

    /**
     * Composite index: Radix Trie (IP) + Hash Map (Port)
     * Total complexity: O(32) + O(1) = O(1)
     */
    template <typename T>
    class CompositeRuleIndex {
    public:
        CompositeRuleIndex() : root(std::make_unique<IndexedTrieNode<T>>()) {}

        /**
         * Inserts a rule into the composite index.
         * The rule is indexed by:
         *   1. Its source IP (in the Radix Trie)
         *   2. Its destination port (in the node's PortIndex)
         */
        void insert(T* rule) {
            for (const auto& cidr_str : rule->src_ips) {
                uint32_t ip;
                int prefix_len;

                if (!parse_cidr(cidr_str, ip, prefix_len)) continue;

                IndexedTrieNode<T>* current = root.get();
                
                for (int i = 0; i < prefix_len; ++i) {
                    bool bit = (ip >> (31 - i)) & 1;

                    if (bit) {
                        if (!current->right) 
                            current->right = std::make_unique<IndexedTrieNode<T>>();
                        current = current->right.get();
                    } else {
                        if (!current->left) 
                            current->left = std::make_unique<IndexedTrieNode<T>>();
                        current = current->left.get();
                    }
                }

                // Add rule to the PortIndex of this node
                current->port_index.add_rule(rule);
            }
        }

        /**
         * Composite lookup: IP + Port in O(1).
         * Returns rules matching EXACTLY this IP:Port combination.
         */
        std::vector<const T*> lookup(uint32_t src_ip_host_order, uint16_t dst_port) const {
            std::vector<const T*> all_matches;
            const IndexedTrieNode<T>* current = root.get();

            // Collect from root (0.0.0.0/0)
            auto root_rules = current->port_index.get_rules(dst_port);
            all_matches.insert(all_matches.end(), root_rules.begin(), root_rules.end());

            // Descend into the Trie
            for (int i = 0; i < 32; ++i) {
                bool bit = (src_ip_host_order >> (31 - i)) & 1;

                if (bit) {
                    if (!current->right) break;
                    current = current->right.get();
                } else {
                    if (!current->left) break;
                    current = current->left.get();
                }

                // Collect rules from this node matching the port
                auto node_rules = current->port_index.get_rules(dst_port);
                all_matches.insert(all_matches.end(), node_rules.begin(), node_rules.end());
            }

            return all_matches;
        }

    private:
        std::unique_ptr<IndexedTrieNode<T>> root;

        static bool parse_cidr(const std::string& cidr, uint32_t& out_ip, int& out_len) {
            // Special case "any" = 0.0.0.0/0
            if (cidr == "any" || cidr == "0.0.0.0/0") {
                out_ip = 0;
                out_len = 0;
                return true;
            }

            size_t slash_pos = cidr.find('/');
            std::string ip_part = (slash_pos == std::string::npos) ? cidr : cidr.substr(0, slash_pos);
            
            struct in_addr addr;
            if (inet_pton(AF_INET, ip_part.c_str(), &addr) != 1) return false;
            out_ip = ntohl(addr.s_addr);

            if (slash_pos != std::string::npos) {
                try {
                    out_len = std::stoi(cidr.substr(slash_pos + 1));
                    if (out_len < 0 || out_len > 32) return false;
                } catch (...) { return false; }
            } else {
                out_len = 32;
            }
            return true;
        }
    };

}

#endif //FOX_FASTPATH_RULE_INDEX_HPP

#ifndef FOX_FASTPATH_RULE_INDEX_HPP
#define FOX_FASTPATH_RULE_INDEX_HPP

/**
 * RuleIndex - Index composite IP + Port pour lookup O(1)
 * 
 * PROBLÈME RÉSOLU:
 * ================
 * L'ancien Radix Trie retournait TOUTES les règles avec src_ip=any (214 règles!)
 * car toutes matchaient 0.0.0.0/0 à la racine du Trie.
 * Résultat: Scan linéaire O(N) de toutes les règles = PIRE que Snort!
 * 
 * SOLUTION:
 * =========
 * Index à deux niveaux:
 *   1. Radix Trie sur IP Source (comme avant)
 *   2. Hash Map sur Port Destination (NOUVEAU)
 * 
 * Complexité: O(32) + O(1) = O(1) constant
 * 
 * STRUCTURE:
 * ==========
 * IP Source → {
 *     port 80   → [règle1, règle2]
 *     port 443  → [règle3]
 *     port ANY  → [règle4, règle5]  // Règles avec dst_port = any
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

    // Port spécial pour les règles qui matchent "any" port
    static constexpr uint32_t PORT_ANY = 0xFFFFFFFF;

    /**
     * Index des règles par port destination.
     * Permet un lookup O(1) après le filtrage IP.
     */
    template <typename T>
    class PortIndex {
    public:
        /**
         * Ajoute une règle à l'index.
         * Si la règle a des ports spécifiques, indexe par chaque port.
         * Si la règle a port=any, indexe sous PORT_ANY.
         */
        void add_rule(T* rule) {
            if (rule->dst_ports.empty()) {
                // Port = any → accessible via PORT_ANY
                any_port_rules.push_back(rule);
            } else {
                // Indexer par chaque port/range
                for (const auto& range : rule->dst_ports) {
                    // Pour les ranges larges (ex: 0-65535), on les met dans any_port
                    if (range.start == 0 && range.end == 65535) {
                        any_port_rules.push_back(rule);
                    } else if (range.end - range.start > 100) {
                        // Range trop large pour indexer individuellement
                        // On le met dans une liste de ranges à vérifier
                        wide_range_rules.push_back(rule);
                    } else {
                        // Range petit: indexer chaque port individuellement
                        for (uint32_t p = range.start; p <= range.end; ++p) {
                            port_map[p].push_back(rule);
                        }
                    }
                }
            }
        }

        /**
         * Récupère les règles qui matchent un port donné.
         * Complexité: O(1) pour le lookup + O(k) pour les rules any/wide
         */
        std::vector<const T*> get_rules(uint16_t port) const {
            std::vector<const T*> result;
            
            // 1. Règles avec ce port spécifique
            auto it = port_map.find(port);
            if (it != port_map.end()) {
                for (T* r : it->second) {
                    result.push_back(r);
                }
            }
            
            // 2. Règles avec port = any
            for (T* r : any_port_rules) {
                result.push_back(r);
            }
            
            // 3. Règles avec ranges larges (vérification nécessaire)
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
        std::vector<T*> any_port_rules;   // Règles avec port = any (0-65535)
        std::vector<T*> wide_range_rules; // Règles avec ranges larges à vérifier
    };

    /**
     * Nœud du Radix Trie avec index de ports intégré.
     */
    template <typename T>
    struct IndexedTrieNode {
        std::unique_ptr<IndexedTrieNode> left;
        std::unique_ptr<IndexedTrieNode> right;
        PortIndex<T> port_index;  // Index des ports pour ce préfixe IP

        bool has_rules() const { return true; } // Simplifié
    };

    /**
     * Index composite: Radix Trie (IP) + Hash Map (Port)
     * Complexité totale: O(32) + O(1) = O(1)
     */
    template <typename T>
    class CompositeRuleIndex {
    public:
        CompositeRuleIndex() : root(std::make_unique<IndexedTrieNode<T>>()) {}

        /**
         * Insère une règle dans l'index composite.
         * La règle est indexée par:
         *   1. Son IP source (dans le Radix Trie)
         *   2. Son port destination (dans le PortIndex du nœud)
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

                // Ajouter la règle dans le PortIndex de ce nœud
                current->port_index.add_rule(rule);
            }
        }

        /**
         * Lookup composite: IP + Port en O(1).
         * Retourne les règles qui matchent EXACTEMENT cette combinaison IP:Port.
         */
        std::vector<const T*> lookup(uint32_t src_ip_host_order, uint16_t dst_port) const {
            std::vector<const T*> all_matches;
            const IndexedTrieNode<T>* current = root.get();

            // Collecter depuis la racine (0.0.0.0/0)
            auto root_rules = current->port_index.get_rules(dst_port);
            all_matches.insert(all_matches.end(), root_rules.begin(), root_rules.end());

            // Descendre dans le Trie
            for (int i = 0; i < 32; ++i) {
                bool bit = (src_ip_host_order >> (31 - i)) & 1;

                if (bit) {
                    if (!current->right) break;
                    current = current->right.get();
                } else {
                    if (!current->left) break;
                    current = current->left.get();
                }

                // Collecter les règles de ce nœud qui matchent le port
                auto node_rules = current->port_index.get_rules(dst_port);
                all_matches.insert(all_matches.end(), node_rules.begin(), node_rules.end());
            }

            return all_matches;
        }

    private:
        std::unique_ptr<IndexedTrieNode<T>> root;

        static bool parse_cidr(const std::string& cidr, uint32_t& out_ip, int& out_len) {
            // Cas spécial "any" = 0.0.0.0/0
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

#endif // FOX_FASTPATH_RULE_INDEX_HPP

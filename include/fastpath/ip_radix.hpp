#ifndef FOX_FASTPATH_IP_RADIX_HPP
#define FOX_FASTPATH_IP_RADIX_HPP

#include <cstdint>
#include <vector>
#include <memory>
#include <optional>
#include <string>
//Inclusion explicite pour inet_pton et ntohl
#include <arpa/inet.h>
#include <netinet/in.h> 
#include "../core/types.hpp"

namespace fox::fastpath {

    /**
     * Radix Trie Node.
     * MODIFIED: Stores a LIST of rules instead of a single one.
     * Reason: Multiple rules can have the same source IP but different ports.
     */
    template <typename T>
    struct TrieNode {
        std::unique_ptr<TrieNode> left;  // Bit 0
        std::unique_ptr<TrieNode> right; // Bit 1
        std::vector<T*> payloads;        // List of associated rules (may be empty)

        bool is_leaf() const { return !payloads.empty(); }
    };

    /**
     * Radix Trie specialized for IPv4 (Key = uint32_t).
     * Lookup Complexity: O(32) -> O(1) constant.
     * 
     * MODIFIED: Now returns a LIST of candidate rules.
     * The Engine must then verify ports for each candidate.
     */
    template <typename T>
    class IPRadixTrie {
    public:
        IPRadixTrie() : root(std::make_unique<TrieNode<T>>()) {}

        /**
         * Inserts a value associated with a CIDR.
         * @param cidr_str Format "192.168.1.0/24"
         * @param value Pointer to the rule (object must outlive the Trie)
         */
        void insert(const std::string& cidr_str, T* value) {
            uint32_t ip;
            int prefix_len;

            if (!parse_cidr(cidr_str, ip, prefix_len)) {
                return;
            }

            TrieNode<T>* current = root.get();
            
            // Traverse bits of the prefix
            for (int i = 0; i < prefix_len; ++i) {
                // Bit extraction i (MSB to LSB)
                bool bit = (ip >> (31 - i)) & 1;

                if (bit) {
                    if (!current->right) current->right = std::make_unique<TrieNode<T>>();
                    current = current->right.get();
                } else {
                    if (!current->left) current->left = std::make_unique<TrieNode<T>>();
                    current = current->left.get();
                }
            }

            // MODIFIED: Append to list instead of overwriting
            current->payloads.push_back(value);
        }

        /**
         * Search for ALL matching rules (Longest Prefix Match + ancestors).
         * @param ip_net_order IP in Network Byte Order (Big Endian)
         * @return Vector of pointers to candidate rules
         */
        std::vector<const T*> lookup_all(uint32_t ip_net_order) const {
            return lookup_all_internal(ntohl(ip_net_order));
        }

        /**
         * Search with IP already in Host Order.
         * @param ip_host_order IP in Host Byte Order
         * @return Vector of candidate rules
         */
        std::vector<const T*> lookup_all_host_order(uint32_t ip_host_order) const {
            return lookup_all_internal(ip_host_order);
        }

        /**
         * LEGACY: Returns the first rule found (for backward compatibility).
         * DEPRECATED: Use lookup_all_host_order instead.
         */
        const T* lookup_host_order(uint32_t ip_host_order) const {
            auto results = lookup_all_internal(ip_host_order);
            return results.empty() ? nullptr : results[0];
        }

    private:
        std::unique_ptr<TrieNode<T>> root;

        std::vector<const T*> lookup_all_internal(uint32_t ip) const {
            std::vector<const T*> all_matches;
            const TrieNode<T>* current = root.get();

            //Collecter les règles de la racine (ex: 0.0.0.0/0)
            for (const T* p : current->payloads) {
                all_matches.push_back(p);
            }

            for (int i = 0; i < 32; ++i) {
                bool bit = (ip >> (31 - i)) & 1;

                if (bit) {
                    if (!current->right) break;
                    current = current->right.get();
                } else {
                    if (!current->left) break;
                    current = current->left.get();
                }

                //Collecter toutes les règles de ce nœud
                for (const T* p : current->payloads) {
                    all_matches.push_back(p);
                }
            }

            return all_matches;
        }

        //Helper parsing CIDR (ex: "10.0.0.1/24")
        bool parse_cidr(const std::string& cidr, uint32_t& out_ip, int& out_len) {
            size_t slash_pos = cidr.find('/');
            std::string ip_part = (slash_pos == std::string::npos) ? cidr : cidr.substr(0, slash_pos);
            
            if (inet_pton(AF_INET, ip_part.c_str(), &out_ip) != 1) return false;
            
            //inet_pton donne du Network Byte Order, on convertit en Host pour le Trie
            out_ip = ntohl(out_ip);

            if (slash_pos != std::string::npos) {
                try {
                    out_len = std::stoi(cidr.substr(slash_pos + 1));
                    if (out_len < 0 || out_len > 32) return false;
                } catch (...) { return false; }
            } else {
                out_len = 32; ///32 par défaut si pas de masque
            }
            return true;
        }
    };
}

#endif //FOX_FASTPATH_IP_RADIX_HPP
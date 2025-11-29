#ifndef FOX_FASTPATH_IP_RADIX_HPP
#define FOX_FASTPATH_IP_RADIX_HPP

#include <cstdint>
#include <vector>
#include <memory>
#include <optional>
#include <string>
// Inclusion explicite pour inet_pton et ntohl
#include <arpa/inet.h>
#include <netinet/in.h> 
#include "../core/types.hpp"

namespace fox::fastpath {

    /**
     * Nœud du Radix Trie.
     * Optimisé pour la localité de cache (taille minimale).
     */
    template <typename T>
    struct TrieNode {
        std::unique_ptr<TrieNode> left;  // Bit 0
        std::unique_ptr<TrieNode> right; // Bit 1
        T* payload = nullptr;            // Donnée associée (ex: RuleDefinition*)

        bool is_leaf() const { return payload != nullptr; }
    };

    /**
     * Radix Trie spécialisé pour IPv4 (Key = uint32_t).
     * Complexité Lookup : O(32) -> O(1) constant.
     */
    template <typename T>
    class IPRadixTrie {
    public:
        IPRadixTrie() : root(std::make_unique<TrieNode<T>>()) {}

        /**
         * Insère une valeur associée à un CIDR.
         * @param cidr_str Format "192.168.1.0/24"
         * @param value Pointeur vers la règle (l'objet doit survivre au Trie)
         */
        void insert(const std::string& cidr_str, T* value) {
            uint32_t ip;
            int prefix_len;

            if (!parse_cidr(cidr_str, ip, prefix_len)) {
                // En prod, on loggerait une erreur ici.
                return;
            }

            TrieNode<T>* current = root.get();
            
            // Parcours des bits du préfixe
            for (int i = 0; i < prefix_len; ++i) {
                // Extraction du bit i (de poids fort vers faible)
                bool bit = (ip >> (31 - i)) & 1;

                if (bit) {
                    if (!current->right) current->right = std::make_unique<TrieNode<T>>();
                    current = current->right.get();
                } else {
                    if (!current->left) current->left = std::make_unique<TrieNode<T>>();
                    current = current->left.get();
                }
            }

            // Assignation du payload au nœud final
            // Note: En cas d'écrasement (règles dupliquées), la dernière gagne.
            // L'optimiseur Python est censé avoir fusionné les doublons.
            current->payload = value;
        }

        /**
         * Recherche le match le plus spécifique (Longest Prefix Match).
         * @param ip_net_order IP en Network Byte Order (Big Endian) provenant du header IP brut
         * @return Pointeur vers la règle ou nullptr
         */
        const T* lookup(uint32_t ip_net_order) const {
            return lookup_internal(ntohl(ip_net_order));
        }

        /**
         * Recherche avec IP déjà en Host Order (depuis Packet::src_ip()/dst_ip()).
         * @param ip_host_order IP en Host Byte Order
         * @return Pointeur vers la règle ou nullptr
         */
        const T* lookup_host_order(uint32_t ip_host_order) const {
            return lookup_internal(ip_host_order);
        }

    private:
        std::unique_ptr<TrieNode<T>> root;

        const T* lookup_internal(uint32_t ip) const {
            const TrieNode<T>* current = root.get();
            const T* last_match = nullptr;

            // On note le match racine s'il existe (ex: règle 0.0.0.0/0)
            if (current->payload) last_match = current->payload;

            for (int i = 0; i < 32; ++i) {
                bool bit = (ip >> (31 - i)) & 1;

                if (bit) {
                    if (!current->right) break;
                    current = current->right.get();
                } else {
                    if (!current->left) break;
                    current = current->left.get();
                }

                // Si ce nœud contient une règle, c'est un candidat plus spécifique
                if (current->payload) {
                    last_match = current->payload;
                }
            }

            return last_match;
        }

        // Helper parsing CIDR (ex: "10.0.0.1/24")
        bool parse_cidr(const std::string& cidr, uint32_t& out_ip, int& out_len) {
            size_t slash_pos = cidr.find('/');
            std::string ip_part = (slash_pos == std::string::npos) ? cidr : cidr.substr(0, slash_pos);
            
            if (inet_pton(AF_INET, ip_part.c_str(), &out_ip) != 1) return false;
            
            // inet_pton donne du Network Byte Order, on convertit en Host pour le Trie
            out_ip = ntohl(out_ip);

            if (slash_pos != std::string::npos) {
                try {
                    out_len = std::stoi(cidr.substr(slash_pos + 1));
                    if (out_len < 0 || out_len > 32) return false;
                } catch (...) { return false; }
            } else {
                out_len = 32; // /32 par défaut si pas de masque
            }
            return true;
        }
    };
}

#endif // FOX_FASTPATH_IP_RADIX_HPP
#ifndef FOX_CORE_FLOW_KEY_HPP
#define FOX_CORE_FLOW_KEY_HPP

#include <cstdint>
#include <functional>
#include <algorithm>
#include <tuple>

namespace fox::core {

    /**
     * Clé de flux CANONIQUE (bidirectionnelle).
     * 
     * CORRECTION CRITIQUE : Une connexion TCP a deux directions (client→server, server→client).
     * Avec une clé non-canonique, les paquets dans les deux sens créent des entrées différentes.
     * Résultat : le verdict DROP n'est pas appliqué aux paquets retour.
     * 
     * Solution : Canonicaliser en triant IPs puis Ports.
     * Ainsi FlowKey(A,B,p1,p2) == FlowKey(B,A,p2,p1)
     */
    struct FlowKey {
        uint32_t ip_low;
        uint32_t ip_high;
        uint16_t port_low;
        uint16_t port_high;

        // Constructeur par défaut
        FlowKey() : ip_low(0), ip_high(0), port_low(0), port_high(0) {}

        // Constructeur avec canonicalisation automatique (Host Order IPs)
        FlowKey(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port) {
            if (src_ip < dst_ip) {
                ip_low = src_ip;
                ip_high = dst_ip;
                port_low = src_port;
                port_high = dst_port;
            } else if (dst_ip < src_ip) {
                ip_low = dst_ip;
                ip_high = src_ip;
                port_low = dst_port;
                port_high = src_port;
            } else {
                // IPs identiques (rare mais possible en loopback)
                ip_low = src_ip;
                ip_high = dst_ip;
                port_low = std::min(src_port, dst_port);
                port_high = std::max(src_port, dst_port);
            }
        }

        bool operator==(const FlowKey& other) const {
            return std::tie(ip_low, ip_high, port_low, port_high) == 
                   std::tie(other.ip_low, other.ip_high, other.port_low, other.port_high);
        }
    };

    /**
     * Hash function optimisée (FNV-1a simplifié) pour FlowKey canonique.
     */
    struct FlowKeyHash {
        std::size_t operator()(const FlowKey& k) const {
            size_t h = 2166136261u;
            h = (h ^ k.ip_low) * 16777619u;
            h = (h ^ k.ip_high) * 16777619u;
            uint32_t ports = (static_cast<uint32_t>(k.port_low) << 16) | k.port_high;
            h = (h ^ ports) * 16777619u;
            return h;
        }
    };
}

#endif // FOX_CORE_FLOW_KEY_HPP
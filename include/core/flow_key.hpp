#ifndef FOX_CORE_FLOW_KEY_HPP
#define FOX_CORE_FLOW_KEY_HPP

#include <cstdint>
#include <functional> // pour std::hash

namespace fox::core {

    /**
     * Identifiant unique d'un flux (5-tuple simplifié sans proto car implicite TCP).
     */
    struct FlowKey {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t src_port;
        uint16_t dst_port;

        bool operator==(const FlowKey& other) const {
            return src_ip == other.src_ip && dst_ip == other.dst_ip &&
                   src_port == other.src_port && dst_port == other.dst_port;
        }
    };

    /**
     * Hash function optimisée pour utiliser FlowKey dans un unordered_map.
     */
    struct FlowKeyHash {
        std::size_t operator()(const FlowKey& k) const {
            // Hash combine rapide (XOR + Shift)
            return ((std::hash<uint32_t>()(k.src_ip) ^ (std::hash<uint32_t>()(k.dst_ip) << 1)) >> 1) ^
                   (std::hash<uint16_t>()(k.src_port) << 1) ^ (std::hash<uint16_t>()(k.dst_port) << 2);
        }
    };
}

#endif // FOX_CORE_FLOW_KEY_HPP
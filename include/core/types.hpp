#ifndef FOX_CORE_TYPES_HPP
#define FOX_CORE_TYPES_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <netinet/in.h> // For IPPROTO_TCP, etc.
#include <msgpack.hpp>
#include "verdict.hpp"

namespace fox::core {

    /**
     * Binary representation of a CIDR for fast comparison.
     * No more strings required at runtime!
     */
    struct Cidr {
        uint32_t network; 
        uint32_t mask;    
    };

    /**
     * Optimized representation of a port range.
     * Maps the Python [start, end] format without dynamic allocation.
     */
    struct PortRange {
        uint16_t start;
        uint16_t end;

        // The ARRAY macro tells msgpack it's a [a, b] array and not an object {a:.., b:..}
        MSGPACK_DEFINE_ARRAY(start, end);
    };

    /**
     * DTO (Data Transfer Object) for rule loading.
     * Corresponds to an entry in the rules_config.msgpack list.
     */
    struct RuleDefinition {
        uint32_t id;                 
        std::string proto;           
        
        // IPs as CIDR strings (e.g., "10.0.0.0/8") - Loaded from MsgPack
        std::vector<std::string> src_ips;
        std::vector<std::string> dst_ips;
        
        // OPTIMIZED Data (Binary) - Filled by Loader after loading
        // This field is NOT in the msgpack file, it's calculated at startup
        std::vector<Cidr> optimized_dst_ips;
        
        // Optimized port ranges
        std::vector<PortRange> src_ports;
        std::vector<PortRange> dst_ports;
        
        std::string direction;       
        uint32_t hs_id;              
        std::string action;
        
        // FIELDS FOR MULTI-PATTERN LOGIC (without HS_FLAG_COMBINATION)
        // HS_FLAG_COMBINATION is NOT supported in HS_MODE_STREAM
        // So AND/OR logic is implemented directly in C++
        std::vector<uint32_t> atomic_ids;  // List of Hyperscan atomic IDs
        bool is_multi = false;             // True if rule has multiple patterns
        bool is_or = false;                // True=OR (any match suffices), False=AND (all must match)

        // --- Fast conversion helpers ---

        // Converts "tcp" -> IPPROTO_TCP (6)
        uint8_t get_proto_id() const {
            if (proto == "tcp") return IPPROTO_TCP;
            if (proto == "udp") return IPPROTO_UDP;
            if (proto == "icmp") return IPPROTO_ICMP;
            return 0; // IPPROTO_IP (Any)
        }

        Verdict get_verdict() const {
            // ANY rule with a pattern match = DROP
            // We unify alert/drop for early rejection efficiency.
            // Pure L3/L4 rules (hs_id=0) are handled separately in Engine.
            return Verdict::DROP;
        }

        // MessagePack Binding (Case Sensitive with Python src/exporter.py !)
        // Note: optimized_dst_ips is NOT included as it doesn't exist in the file
        MSGPACK_DEFINE_MAP(id, proto, src_ips, dst_ips, src_ports, dst_ports, direction, hs_id, atomic_ids, is_multi, is_or, action);
    };

    /**
     * The msgpack file is a root list, not an object.
     * Configuration type is defined as a simple vector.
     */
    using RulesConfig = std::vector<RuleDefinition>;

}

#endif //FOX_CORE_TYPES_HPP
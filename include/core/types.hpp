#ifndef FOX_CORE_TYPES_HPP
#define FOX_CORE_TYPES_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <netinet/in.h> // Pour IPPROTO_TCP, etc.
#include <msgpack.hpp>
#include "verdict.hpp"

namespace fox::core {

    /**
     * Représentation binaire d'un CIDR pour comparaison rapide.
     * Plus besoin de strings au runtime !
     */
    struct Cidr {
        uint32_t network; // IP Host Order (masquée)
        uint32_t mask;    // Masque binaire Host Order
    };

    /**
     * Représentation optimisée d'une plage de ports.
     * Mappe le format Python [start, end] sans allocation dynamique.
     */
    struct PortRange {
        uint16_t start;
        uint16_t end;

        // La macro ARRAY indique à msgpack que c'est un tableau [a, b] et non un objet {a:.., b:..}
        MSGPACK_DEFINE_ARRAY(start, end);
    };

    /**
     * DTO (Data Transfer Object) pour le chargement des règles.
     * Correspond à une entrée de la liste dans rules_config.msgpack.
     */
    struct RuleDefinition {
        uint32_t id;                 
        std::string proto;           
        
        // IPs en chaînes CIDR (ex: "10.0.0.0/8") - Chargées depuis MsgPack
        std::vector<std::string> src_ips;
        std::vector<std::string> dst_ips;
        
        // Données OPTIMISÉES (Binaires) - Remplies par le Loader après chargement
        // Ce champ n'est PAS dans le fichier msgpack, il est calculé au démarrage
        std::vector<Cidr> optimized_dst_ips;
        
        // Plages de ports optimisées
        std::vector<PortRange> src_ports;
        std::vector<PortRange> dst_ports;
        
        std::string direction;       
        uint32_t hs_id;              
        std::string action;          

        // --- Helpers de conversion rapide ---

        // Convertit "tcp" -> IPPROTO_TCP (6)
        uint8_t get_proto_id() const {
            if (proto == "tcp") return IPPROTO_TCP;
            if (proto == "udp") return IPPROTO_UDP;
            if (proto == "icmp") return IPPROTO_ICMP;
            return 0; // IPPROTO_IP (Any)
        }

        Verdict get_verdict() const {
            // Optimisation: on suppose que l'input est validé par le Python
            if (action[0] == 'd' || action[0] == 'r') return Verdict::DROP; // drop/reject
            return Verdict::ACCEPT;
        }

        // Binding MessagePack (Case Sensitive avec Python src/exporter.py !)
        // Note: optimized_dst_ips n'est PAS inclus car il n'existe pas dans le fichier
        MSGPACK_DEFINE_MAP(id, proto, src_ips, dst_ips, src_ports, dst_ports, direction, hs_id, action);
    };

    /**
     * Le fichier msgpack est une liste racine, pas un objet.
     * On définit donc le type de configuration comme un simple vecteur.
     */
    using RulesConfig = std::vector<RuleDefinition>;

}

#endif // FOX_CORE_TYPES_HPP
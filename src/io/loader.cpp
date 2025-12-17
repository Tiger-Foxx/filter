#include "../../include/io/loader.hpp"
#include "../../include/utils/logger.hpp"
#include "../../include/core/types.hpp"
#include <fstream>
#include <sstream>
#include <vector>
#include <cstdlib> // system()
#include <msgpack.hpp>
#include <arpa/inet.h> // inet_pton

namespace fox::io {

    // Helper statique pour convertir "192.168.1.0/24" -> struct Cidr binaire
    static fox::core::Cidr parse_cidr_binary(const std::string& cidr_str) {
        fox::core::Cidr res{0, 0};

        // Cas "any" ou "0.0.0.0/0" -> Mask=0 matche tout
        if (cidr_str == "any" || cidr_str == "0.0.0.0/0") {
            return res; // Net=0, Mask=0 -> Match tout
        }

        size_t slash = cidr_str.find('/');
        std::string ip_part = (slash == std::string::npos) ? cidr_str : cidr_str.substr(0, slash);
        int prefix = (slash == std::string::npos) ? 32 : std::stoi(cidr_str.substr(slash + 1));

        struct in_addr addr;
        if (inet_pton(AF_INET, ip_part.c_str(), &addr) == 1) {
            res.network = ntohl(addr.s_addr);
            // Gestion safe du shift (décalage de 32 bits est undefined en C++)
            if (prefix == 0) res.mask = 0;
            else res.mask = (~0u << (32 - prefix));
            
            // On applique le masque au réseau pour normaliser (ex: 192.168.1.5/24 -> 192.168.1.0)
            res.network &= res.mask;
        }
        return res;
    }

    bool Loader::load_all(
        fox::fastpath::CompositeRuleIndex<fox::core::RuleDefinition>& index,
        fox::deep::HSMatcher& matcher
    ) {
        fox::log::info(">>> Starting FoxEngine Loader");

        // 1. Kernel Offload (DÉSACTIVÉ pour les tests - réactiver en production)
        // run_firewall_script(fox::config::PATH_FIREWALL_SCRIPT);
        fox::log::info("Firewall script SKIPPED (test mode)");

        // 2. Deep Inspection Engine
        std::string pattern_path(fox::config::PATH_PATTERNS_DB);
        if (!matcher.init(pattern_path)) {
            fox::log::error("Failed to initialize Hyperscan. Engine will run in L3/L4 only mode.");
        }

        // 3. FastPath Logic - Utilise maintenant CompositeRuleIndex
        std::string rules_path(fox::config::PATH_RULES_CONFIG);
        if (!load_msgpack_config(rules_path, index)) {
            return false; // Fatal: Pas de règles logiques
        }

        fox::log::info(">>> Initialization Complete. Engine Ready.");
        return true;
    }

    void Loader::run_firewall_script(std::string_view script_path) {
        std::string cmd = "bash " + std::string(script_path);
        fox::log::info("Executing Kernel Offload script: " + std::string(script_path));
        
        int ret = std::system(cmd.c_str());
        if (ret != 0) {
            fox::log::error("Firewall script execution returned non-zero code.");
        }
    }

    bool Loader::load_msgpack_config(
        const std::string& msgpack_path,
        fox::fastpath::CompositeRuleIndex<fox::core::RuleDefinition>& index
    ) {
        std::ifstream ifs(msgpack_path, std::ifstream::in | std::ifstream::binary);
        if (!ifs) {
            fox::log::error("Cannot open rules config: " + msgpack_path);
            return false;
        }

        // Lecture intégrale du fichier dans un buffer
        std::stringstream buffer;
        buffer << ifs.rdbuf();
        std::string data = buffer.str();

        fox::log::info("Loading Logic Rules (" + std::to_string(data.size()) + " bytes)...");

        try {
            // Désérialisation msgpack
            msgpack::object_handle oh = msgpack::unpack(data.data(), data.size());
            msgpack::object obj = oh.get();
            
            // Conversion vers notre vector<RuleDefinition>
            fox::core::RulesConfig rules;
            obj.convert(rules);

            fox::log::info("Parsed " + std::to_string(rules.size()) + " optimized rules.");

            // PEUPLEMENT DE L'INDEX COMPOSITE (IP + Port)
            int rule_count = 0;
            for (auto& rule_dto : rules) {
                
                // Conversion des string Dst IPs en binaire
                rule_dto.optimized_dst_ips.reserve(rule_dto.dst_ips.size());
                for (const auto& s : rule_dto.dst_ips) {
                    rule_dto.optimized_dst_ips.push_back(parse_cidr_binary(s));
                }

                // Allocation persistante
                auto* rule_ptr = new fox::core::RuleDefinition(rule_dto);

                // Insertion dans l'index composite (IP + Port)
                index.insert(rule_ptr);
                rule_count++;
            }
            
            fox::log::info("Composite Index populated with " + std::to_string(rule_count) + " rules.");

        } catch (const std::exception& e) {
            fox::log::error(std::string("Msgpack unpacking failed: ") + e.what());
            return false;
        }

        return true;
    }
}
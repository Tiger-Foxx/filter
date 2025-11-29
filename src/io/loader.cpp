#include "../../include/io/loader.hpp"
#include "../../include/logger.hpp"
#include "../../include/core/types.hpp"
#include <fstream>
#include <vector>
#include <cstdlib> // system()

namespace fox::io {

    bool Loader::load_all(
        fox::fastpath::IPRadixTrie<fox::core::RuleDefinition>& trie,
        fox::deep::HSMatcher& matcher
    ) {
        fox::log::info(">>> Starting FoxEngine Loader");

        // 1. Kernel Offload
        run_firewall_script(fox::config::PATH_FIREWALL_SCRIPT);

        // 2. Deep Inspection Engine
        std::string pattern_path(fox::config::PATH_PATTERNS_DB);
        if (!matcher.init(pattern_path)) {
            fox::log::error("Failed to initialize Hyperscan. Engine will run in L3/L4 only mode.");
            // On ne return false pas forcément, on peut continuer en mode dégradé (IP only)
        }

        // 3. FastPath Logic
        std::string rules_path(fox::config::PATH_RULES_CONFIG);
        if (!load_msgpack_config(rules_path, trie)) {
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
        fox::fastpath::IPRadixTrie<fox::core::RuleDefinition>& trie
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

            // PEUPLEMENT DU RADIX TRIE
            // Attention : Les règles doivent survivre au Loader.
            // Dans une implémentation "Research Grade" pure, on utiliserait un Arena Allocator.
            // Ici, on va faire une fuite de mémoire volontaire (static storage) ou 
            // passer la propriété au Trie.
            // Pour simplifier cette étape et respecter ton architecture actuelle :
            // On alloue chaque règle sur le tas et on donne le pointeur au Trie.
            // C'est acceptable car fait une seule fois au boot.
            
            int insertion_count = 0;
            for (const auto& rule_dto : rules) {
                // Allocation persistante (jamais libérée tant que le moteur tourne)
                auto* rule_ptr = new fox::core::RuleDefinition(rule_dto);

                // Insertion pour chaque IP Source
                for (const auto& cidr : rule_ptr->src_ips) {
                    trie.insert(cidr, rule_ptr);
                    insertion_count++;
                }
                
                // Note: La fusion Src/Dst est gérée par l'Optimizer Python.
                // Si la règle est "Src A -> Dst B", l'optimizer a généré une entrée logique.
                // Ici on indexe par Source IP comme clé primaire du Trie (choix d'architecture courant).
                // *Critique*: Si on veut filtrer par Dst IP aussi, il faudrait un second Trie 
                // ou un Trie multidimensionnel. Pour l'instant, indexons sur SRC.
            }
            
            fox::log::info("Radix Trie populated with " + std::to_string(insertion_count) + " nodes.");

        } catch (const std::exception& e) {
            fox::log::error(std::string("Msgpack unpacking failed: ") + e.what());
            return false;
        }

        return true;
    }
}
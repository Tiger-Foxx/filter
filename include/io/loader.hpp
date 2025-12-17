#ifndef FOX_IO_LOADER_HPP
#define FOX_IO_LOADER_HPP

#include <string>
#include <string_view>
#include "../fastpath/rule_index.hpp"
#include "../deep/hs_matcher.hpp"
#include "../config.hpp" // Pour les chemins PATH_*

namespace fox::io {

    class Loader {
    public:
        /**
         * Charge la configuration complète.
         * 1. Exécute firewall.sh
         * 2. Compile patterns.txt dans matcher
         * 3. Charge rules_config.msgpack dans l'index composite
         */
        static bool load_all(
            fox::fastpath::CompositeRuleIndex<fox::core::RuleDefinition>& index,
            fox::deep::HSMatcher& matcher
        );

    private:
        static void run_firewall_script(std::string_view script_path);
        
        static bool load_msgpack_config(
            const std::string& msgpack_path,
            fox::fastpath::CompositeRuleIndex<fox::core::RuleDefinition>& index
        );
    };
}

#endif // FOX_IO_LOADER_HPP
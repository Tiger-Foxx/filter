#ifndef FOX_LOGGER_HPP
#define FOX_LOGGER_HPP

#include <iostream>
#include <string_view>

namespace fox::log {

    // Log critique : Toujours affiché (stderr)
    // Utilisé pour: Echec init, malloc fail, mmap fail
    inline void error(std::string_view msg) {
        std::cerr << "[CRITICAL] " << msg << std::endl;
    }

#ifndef NDEBUG
    // Log debug : Affiché seulement en mode debug
    inline void debug(std::string_view msg) {
        std::cout << "[DEBUG] " << msg << std::endl;
    }
#else
    // En release, cette fonction est optimisée (no-op) et disparait du binaire
    inline void debug(std::string_view) {}
#endif

    // Log info : Pour les étapes majeures (Load ok, Start engine)
    inline void info(std::string_view msg) {
        std::cout << "[INFO] " << msg << std::endl;
    }
}

#endif // FOX_LOGGER_HPP
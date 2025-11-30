#ifndef FOX_CONFIG_HPP
#define FOX_CONFIG_HPP

#include <cstdint>
#include <string_view>

namespace fox::config {

    // --- ARTEFACTS PATHS ---
    // Note: Ces chemins sont relatifs au répertoire d'exécution.
    // Pour la PoC, copier les fichiers depuis optimizer/outputs/ vers filter/data/
    // ou ajuster ces chemins selon votre setup.
    constexpr std::string_view PATH_FIREWALL_SCRIPT = "data/firewall.sh";
    constexpr std::string_view PATH_PATTERNS_DB     = "data/patterns.txt";
    constexpr std::string_view PATH_RULES_CONFIG    = "data/rules_config.msgpack";

    // --- NETWORK CONFIG ---
    constexpr uint16_t NFQUEUE_ID = 0;
    
    // Taille max d'un paquet IP (65535) + Marge pour headers Netlink
    constexpr uint32_t MAX_PACKET_SIZE = 0xFFFF; 
    
    // Taille du buffer socket Kernel (8MB pour encaisser les micro-bursts 10Gbps)
    constexpr uint32_t NETLINK_BUFFER_SIZE = 8 * 1024 * 1024;

    // --- DEEP INSPECTION CONFIG ---
    // Nombre max de flux TCP simultanés en mémoire
    constexpr uint32_t MAX_CONCURRENT_FLOWS = 100000;
    // Timeout d'inactivité pour les flux TCP (en secondes)
    constexpr uint32_t FLOW_TIMEOUT_SEC = 60;
    // Taille max de la fenêtre de réassemblage par flux (1MB)
    constexpr uint32_t MAX_REASSEMBLY_WINDOW = 1024 * 1024;
}

#endif // FOX_CONFIG_HPP
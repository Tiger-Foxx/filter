#ifndef FOX_CONFIG_HPP
#define FOX_CONFIG_HPP

#include <cstdint>
#include <string_view>

namespace fox::config {

    // --- CHEMINS DES ARTEFACTS (Outputs Python) ---
    // Ces fichiers sont mappés en mémoire (mmap) au démarrage.
    constexpr std::string_view PATH_FIREWALL_SCRIPT = "data/firewall.sh";
    constexpr std::string_view PATH_PATTERNS_DB   = "data/patterns.txt";
    constexpr std::string_view PATH_RULES_CONFIG  = "data/rules_config.msgpack";

    // --- CONFIGURATION RESEAU (NFQUEUE) ---
    // Queue ID 0 par défaut (doit matcher la règle iptables)
    constexpr uint16_t NFQUEUE_ID = 0;
    
    // Taille du buffer de copie User/Kernel. 
    // 65535 couvre tout paquet IP théorique.
    constexpr uint32_t MAX_PACKET_SIZE = 0xFFFF;
    
    // Taille du buffer socket Netlink (Kernel buffer)
    // Augmenter pour éviter les drops en cas de burst (ex: 8MB)
    constexpr uint32_t NETLINK_BUFFER_SIZE = 8 * 1024 * 1024;

    // --- CONFIGURATION DPI (TCP REASSEMBLY) ---
    // Nombre maximum de flux TCP suivis simultanément (Memory Pool size)
    // 100k flux * ~200 octets structure = ~20MB RAM (très léger)
    constexpr uint32_t MAX_CONCURRENT_FLOWS = 100000;

    // Temps avant qu'un flux inactif soit purgé (secondes)
    constexpr uint32_t FLOW_TIMEOUT_SEC = 60;

    // Taille max du buffer de réassemblage par flux (protection DoS)
    constexpr uint32_t MAX_STREAM_BUFFER_SIZE = 1 * 1024 * 1024; // 1MB

}

#endif // FOX_CONFIG_HPP
#ifndef FOX_CONFIG_HPP
#define FOX_CONFIG_HPP

#include <cstdint>
#include <string_view>
#include <thread>

namespace fox::config {

    //--- MULTI-THREADING ---
    //Nombre de threads de traitement (0 = auto-detect CPU cores)
    constexpr uint32_t NUM_WORKER_THREADS = 0;
    
    //Nombre de queues NFQUEUE (doit correspondre à iptables --queue-balance)
    //Si 0, utilise NUM_WORKER_THREADS
    constexpr uint32_t NUM_QUEUES = 4;
    
    //Queue ID de départ (les queues seront START_QUEUE_ID à START_QUEUE_ID + NUM_QUEUES - 1)
    constexpr uint16_t START_QUEUE_ID = 0;

    //--- DEBUG MODE ---
    //Mettre à true pour activer les logs verbeux (désactiver en production)
    constexpr bool DEBUG_MODE = false;
    
    //Affiche les N premiers paquets en détail (0 = tous, mais TRÈS lent !)
    constexpr uint32_t DEBUG_FIRST_N_PACKETS = 0;

    //--- ARTEFACTS PATHS ---
    constexpr std::string_view PATH_FIREWALL_SCRIPT = "data/firewall.sh";
    constexpr std::string_view PATH_PATTERNS_DB     = "data/patterns.txt";
    constexpr std::string_view PATH_RULES_CONFIG    = "data/rules_config.msgpack";

    //--- NETWORK CONFIG ---
    constexpr uint16_t NFQUEUE_ID = 0;  //Legacy, utilisé si mono-thread
    
    //Taille max d'un paquet IP (65535) + Marge pour headers Netlink
    constexpr uint32_t MAX_PACKET_SIZE = 0xFFFF; 
    
    //Taille du buffer socket Kernel (8MB pour encaisser les micro-bursts 10Gbps)
    constexpr uint32_t NETLINK_BUFFER_SIZE = 8 * 1024 * 1024;

    //--- DEEP INSPECTION CONFIG ---
    //Nombre max de flux TCP simultanés en mémoire (par thread)
    constexpr uint32_t MAX_CONCURRENT_FLOWS = 50000;
    //Timeout d'inactivité pour les flux TCP (en secondes)
    constexpr uint32_t FLOW_TIMEOUT_SEC = 10;
    //Taille max de la fenêtre de réassemblage par flux (10MB)
    constexpr uint32_t MAX_REASSEMBLY_WINDOW = 10*1024 * 1024;
    
    //--- HELPER FUNCTIONS ---
    inline uint32_t get_num_threads() {
        if (NUM_WORKER_THREADS == 0) {
            uint32_t hw = std::thread::hardware_concurrency();
            return hw > 0 ? hw : 4;
        }
        return NUM_WORKER_THREADS;
    }
    
    inline uint32_t get_num_queues() {
        return NUM_QUEUES > 0 ? NUM_QUEUES : get_num_threads();
    }
}

#endif //FOX_CONFIG_HPP
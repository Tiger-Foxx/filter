/**
 * FOX Engine - Multi-Thread IPS
 * 
 * Architecture Multi-Queue NFQUEUE pour scalabilité linéaire.
 * 
 * Configuration iptables requise:
 *   sudo iptables -A FORWARD -j NFQUEUE --queue-balance 0:3
 * 
 * Le kernel distribue les paquets sur les queues par hash(5-tuple),
 * garantissant que les paquets d'un même flux TCP vont au même thread.
 */

#include "../include/io/loader.hpp"
#include "../include/io/nfqueue.hpp"
#include "../include/utils/logger.hpp"
#include "../include/config.hpp"
#include "../include/fastpath/rule_index.hpp"
#include "../include/deep/hs_matcher.hpp"

#include <csignal>
#include <iostream>

// Pointeur global pour l'arrêt propre via Signal Handler
fox::io::NFQueueMulti* g_queue = nullptr;

void signal_handler(int sig) {
    if (g_queue) {
        std::cout << "\n[SHUTDOWN] Signal " << sig << " received. Stopping engine..." << std::endl;
        g_queue->stop();
    } else {
        exit(0);
    }
}

int main() {
    // 1. Hook Signaux
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    uint32_t num_threads = fox::config::get_num_queues();
    
    fox::log::info("=== FOX ENGINE (Multi-Thread IPS) ===");
    fox::log::info("Threads: " + std::to_string(num_threads));

    // 2. Structures de données Persistantes (Heap)
    auto* index = new fox::fastpath::CompositeRuleIndex<fox::core::RuleDefinition>();
    auto* matcher = new fox::deep::HSMatcher();

    // 3. Chargement (Loader)
    if (!fox::io::Loader::load_all(*index, *matcher)) {
        fox::log::error("Critical: Failed to load configuration.");
        return 1;
    }

    // 4. Init Multi-Queue NFQUEUE
    fox::io::NFQueueMulti nfqueue(fox::config::START_QUEUE_ID, num_threads);
    g_queue = &nfqueue;

    if (!nfqueue.init(index, matcher)) {
        fox::log::error("Critical: Failed to initialize NFQUEUE workers.");
        return 1;
    }

    // 5. Run (Lance tous les threads workers)
    nfqueue.run();

    // 6. Cleanup (Atteint après Ctrl+C)
    delete index;
    delete matcher;
    
    fox::log::info("Bye.");
    return 0;
}
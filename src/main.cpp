#include "../include/io/loader.hpp"
#include "../include/io/nfqueue.hpp"
#include "../include/core/engine.hpp"
#include "../include/utils/logger.hpp"
#include "../include/config.hpp"
// Index composite (IP Trie + Port Hash) pour lookup O(1)
#include "../include/fastpath/rule_index.hpp"
#include "../include/deep/hs_matcher.hpp"

#include <csignal>
#include <iostream>
#include <thread>

// Pointeur global pour l'arrêt propre via Signal Handler
fox::io::NFQueue* g_queue = nullptr;

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

    fox::log::info("=== FOX ENGINE (Research PoC - Composite Index) ===");

    // 2. Structures de données Persistantes (Heap)
    // CompositeRuleIndex = IP Radix Trie + Port Hash Map pour O(1) lookup
    auto* index = new fox::fastpath::CompositeRuleIndex<fox::core::RuleDefinition>();
    auto* matcher = new fox::deep::HSMatcher();

    // 3. Chargement (Loader)
    if (!fox::io::Loader::load_all(*index, *matcher)) {
        fox::log::error("Critical: Failed to load configuration.");
        return 1;
    }

    // 4. Init Engine Singleton
    fox::core::Engine::instance().init(index, matcher);

    // 5. Init Network Interface
    fox::io::NFQueue nfqueue(fox::config::NFQUEUE_ID);
    g_queue = &nfqueue;

    if (!nfqueue.init()) {
        fox::log::error("Critical: Failed to bind NFQUEUE.");
        return 1;
    }

    // 6. Run (Bloquant)
    nfqueue.run();

    // 7. Cleanup (Atteint après Ctrl+C)
    delete index;
    delete matcher;
    
    fox::log::info("Bye.");
    return 0;
}
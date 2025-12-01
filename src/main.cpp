#include "../include/io/loader.hpp"
#include "../include/io/nfqueue.hpp"
#include "../include/core/engine.hpp"
#include "../include/core/engine_fast.hpp"  // Version haute performance
#include "../include/utils/logger.hpp"
#include "../include/config.hpp"
// On inclut les headers concrets pour l'instanciation
#include "../include/fastpath/ip_radix.hpp"
#include "../include/deep/hs_matcher.hpp"

#include <csignal>
#include <iostream>
#include <thread>
#include <cstring>

// === CONFIGURATION DU MODE ===
// Définir USE_FAST_ENGINE=1 pour activer le moteur haute performance
#ifndef USE_FAST_ENGINE
#define USE_FAST_ENGINE 1  // Activé par défaut
#endif

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

void print_stats() {
#if USE_FAST_ENGINE
    auto& engine = fox::core::EngineFast::instance();
    fox::log::info("Stats: " + std::to_string(engine.packets_processed()) + " packets, " +
                   std::to_string(engine.active_tcp_flows()) + " active TCP flows");
#endif
}

int main(int argc, char* argv[]) {
    // 1. Hook Signaux
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

#if USE_FAST_ENGINE
    fox::log::info("=== FOX ENGINE (High Performance Mode) ===");
    fox::log::info("Using: Zero-Copy Ring Buffer + Inline Hyperscan Streaming");
#else
    fox::log::info("=== FOX ENGINE (Standard Mode) ===");
#endif

    // 2. Structures de données Persistantes (Heap)
    // Elles doivent survivre tout le runtime.
    auto* trie = new fox::fastpath::IPRadixTrie<fox::core::RuleDefinition>();
    auto* matcher = new fox::deep::HSMatcher();

    // 3. Chargement (Loader)
    if (!fox::io::Loader::load_all(*trie, *matcher)) {
        fox::log::error("Critical: Failed to load configuration.");
        return 1;
    }

    // 4. Init Engine Singleton
#if USE_FAST_ENGINE
    fox::core::EngineFast::instance().init(trie, matcher);
#else
    fox::core::Engine::instance().init(trie, matcher);
#endif

    // 5. Init Network Interface
    fox::io::NFQueue nfqueue(fox::config::NFQUEUE_ID);
    g_queue = &nfqueue;

    if (!nfqueue.init()) {
        fox::log::error("Critical: Failed to bind NFQUEUE.");
        return 1;
    }

    // 6. Run (Bloquant)
    nfqueue.run();

    // 7. Final Stats
    print_stats();

    // 8. Cleanup (Atteint après Ctrl+C)
    delete trie;
    delete matcher;
    
    fox::log::info("Bye.");
    return 0;
}
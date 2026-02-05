#include "../include/io/loader.hpp"
#include "../include/io/nfqueue.hpp"
#include "../include/utils/logger.hpp"
#include "../include/config.hpp"
#include "../include/fastpath/rule_index.hpp"
#include "../include/deep/hs_matcher.hpp"

#include <csignal>
#include <iostream>

fox::io::NFQueueMulti* g_queue = nullptr;

void signal_handler(int sig) {
    if (g_queue) {
        g_queue->stop();
    } else {
        exit(0);
    }
}

int main() {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    uint32_t num_threads = fox::config::get_num_queues();
    
    fox::log::info("Starting FOX Engine...");
    fox::log::info("Threads count: " + std::to_string(num_threads));

    auto* index = new fox::fastpath::CompositeRuleIndex<fox::core::RuleDefinition>();
    auto* matcher = new fox::deep::HSMatcher();

    if (!fox::io::Loader::load_all(*index, *matcher)) {
        fox::log::error("Critical: Failed to load configuration.");
        return 1;
    }

    //4. Init Multi-Queue NFQUEUE
    fox::io::NFQueueMulti nfqueue(fox::config::START_QUEUE_ID, num_threads);
    g_queue = &nfqueue;

    if (!nfqueue.init(index, matcher)) {
        fox::log::error("Critical: Failed to initialize NFQUEUE workers.");
        return 1;
    }

    //5. Run (Lance tous les threads workers)
    nfqueue.run();

    //6. Cleanup (Atteint après Ctrl+C)
    delete index;
    delete matcher;
    
    fox::log::info("Bye.");
    return 0;
}
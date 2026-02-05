#ifndef FOX_IO_NFQUEUE_HPP
#define FOX_IO_NFQUEUE_HPP

/**
 * NFQueue Multi-Thread - Architecture haute performance
 * 
 * MULTI-QUEUE ARCHITECTURE
 * ========================
 * 
 * Le kernel Linux peut distribuer les paquets sur plusieurs queues
 * via --queue-balance. Chaque queue est traitée par un thread dédié.
 * 
 * iptables -A FORWARD -j NFQUEUE --queue-balance 0:3
 * 
 * Distribution: Hash(5-tuple) → Queue N → Thread N
 * Avantage: Les paquets d'un même flux vont toujours au même thread
 *           → Pas besoin de locks sur les structures de flux TCP
 */

#include <cstdint>
#include <vector>
#include <thread>
#include <atomic>
#include <memory>

// Forward declarations
struct nfq_handle;
struct nfq_q_handle;
struct nfgenmsg;
struct nfq_data;

namespace fox::deep {
    class HSMatcher;
    class TcpReassembler;
}

namespace fox::fastpath {
    template<typename T> class CompositeRuleIndex;
}

namespace fox::core {
    struct RuleDefinition;
}

struct hs_scratch;
typedef struct hs_scratch hs_scratch_t;

namespace fox::io {

    /**
     * Worker thread context - Tout ce dont un thread a besoin
     * Chaque thread a ses propres ressources, pas de locks nécessaires
     */
    struct WorkerContext {
        uint16_t queue_id;
        struct nfq_handle* h = nullptr;
        struct nfq_q_handle* qh = nullptr;
        int fd = -1;
        std::vector<char> buffer;
        
        // Ressources per-thread (pas de partage = pas de locks)
        hs_scratch_t* scratch = nullptr;
        std::unique_ptr<fox::deep::TcpReassembler> reassembler;
        
        // Statistiques
        std::atomic<uint64_t> packets_processed{0};
        std::atomic<uint64_t> packets_dropped{0};
    };

    /**
     * NFQueueMulti - Gestionnaire multi-queue multi-thread
     */
    class NFQueueMulti {
    public:
        NFQueueMulti(uint16_t start_queue_id, uint32_t num_queues);
        ~NFQueueMulti();

        /**
         * Initialise toutes les queues et alloue les ressources per-thread
         */
        bool init(fox::fastpath::CompositeRuleIndex<fox::core::RuleDefinition>* index,
                  fox::deep::HSMatcher* matcher);

        /**
         * Lance tous les worker threads
         */
        void run();

        /**
         * Arrêt propre de tous les threads
         */
        void stop();

        /**
         * Statistiques agrégées
         */
        uint64_t total_packets() const;
        uint64_t total_dropped() const;

    private:
        uint16_t _start_queue_id;
        uint32_t _num_queues;
        std::atomic<bool> _running{false};
        
        // Ressources partagées (read-only après init)
        fox::fastpath::CompositeRuleIndex<fox::core::RuleDefinition>* _index = nullptr;
        fox::deep::HSMatcher* _matcher = nullptr;
        
        // Contextes per-thread
        std::vector<std::unique_ptr<WorkerContext>> _workers;
        std::vector<std::thread> _threads;
        std::vector<void*> _callback_contexts;  // CallbackContext* stockés ici

        // Worker loop
        void worker_loop(WorkerContext* ctx);
        
        // Callback NFQUEUE (appelé par libnetfilter_queue)
        static int packet_callback(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg,
                                   struct nfq_data* nfa, void* data);
    };

    // Alias pour compatibilité
    using NFQueue = NFQueueMulti;
}

#endif // FOX_IO_NFQUEUE_HPP
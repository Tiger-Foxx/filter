#ifndef FOX_IO_NFQUEUE_HPP
#define FOX_IO_NFQUEUE_HPP

#include <cstdint>
#include <vector>

// Forward declarations pour éviter d'inclure les headers C ici
struct nfq_handle;
struct nfq_q_handle;
struct nfgenmsg;
struct nfq_data;

namespace fox::io {

    class NFQueue {
    public:
        explicit NFQueue(uint16_t queue_id);
        ~NFQueue();

        // Initialisation complète (Open, Bind, Set Mode)
        bool init();

        // Boucle principale bloquante
        void run();

        // Arrêt propre
        void stop();

    private:
        uint16_t _queue_id;
        struct nfq_handle* _h = nullptr;
        struct nfq_q_handle* _qh = nullptr;
        int _fd = -1;
        volatile bool _running = false;

        // Buffer de réception membre (Alloué une seule fois à la construction)
        // std::vector garantit un alignement mémoire correct
        std::vector<char> _buffer;

        static int callback(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg,
                            struct nfq_data* nfa, void* data);
    };
}

#endif // FOX_IO_NFQUEUE_HPP
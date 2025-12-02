#include "../../include/io/nfqueue.hpp"
#include "../../include/core/engine.hpp"
#include "../../include/core/packet.hpp"
#include "../../include/utils/logger.hpp"
#include "../../include/config.hpp"

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnfnetlink/libnfnetlink.h> // Nécessaire pour nfnl_rcvbufsiz
#include <linux/netfilter.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <cerrno>
#include <cstring>
#include <span>
#include <iostream>

namespace fox::io {

    NFQueue::NFQueue(uint16_t queue_id) 
        : _queue_id(queue_id) {
        // Pré-allocation du buffer pour éviter tout realloc au runtime
        // On ajoute 4096 octets de marge pour les headers Netlink
        _buffer.resize(fox::config::MAX_PACKET_SIZE + 4096);
    }

    NFQueue::~NFQueue() {
        fox::log::info("Cleaning up NFQUEUE resources...");
        // ORDRE CRITIQUE : D'abord détruire la queue, puis fermer le handle
        if (_qh) {
            nfq_destroy_queue(_qh);
            _qh = nullptr;
        }
        if (_h) {
            // Détacher du protocol family avant de fermer
            nfq_unbind_pf(_h, AF_INET);
            nfq_close(_h);
            _h = nullptr;
        }
        fox::log::info("NFQUEUE resources released.");
    }

    bool NFQueue::init() {
        fox::log::info("Initializing NFQUEUE ID " + std::to_string(_queue_id));

        _h = nfq_open();
        if (!_h) {
            fox::log::error("nfq_open() failed");
            return false;
        }

        if (nfq_unbind_pf(_h, AF_INET) < 0) {
            // Ce n'est pas une erreur critique
            fox::log::error("nfq_unbind_pf() failed (ignored)");
        }

        if (nfq_bind_pf(_h, AF_INET) < 0) {
            fox::log::error("nfq_bind_pf() failed. Are you root?");
            return false;
        }

        _qh = nfq_create_queue(_h, _queue_id, &NFQueue::callback, nullptr);
        if (!_qh) {
            fox::log::error("nfq_create_queue() failed");
            return false;
        }

        // Mode COPY_PACKET : On veut le payload complet
        if (nfq_set_mode(_qh, NFQNL_COPY_PACKET, fox::config::MAX_PACKET_SIZE) < 0) {
            fox::log::error("nfq_set_mode() failed");
            return false;
        }

        // Optimisation Buffer Kernel (Critique pour le débit)
        if (nfnl_rcvbufsiz(nfq_nfnlh(_h), fox::config::NETLINK_BUFFER_SIZE) < 0) {
            fox::log::error("Failed to set socket buffer size (nfnl_rcvbufsiz)");
            // On continue quand même, c'est une optimisation
        }

        _fd = nfq_fd(_h);
        return true;
    }

    void NFQueue::stop() {
        _running = false;
    }

    void NFQueue::run() {
        _running = true;
        fox::log::info(">>> Engine Running (NFQUEUE). Waiting for packets...");
        fox::log::info(">>> Press CTRL+C to stop gracefully.");

        // Configuration pour arrêt propre : poll() avec timeout
        struct pollfd pfd;
        pfd.fd = _fd;
        pfd.events = POLLIN;

        while (_running) {
            // Poll avec timeout de 500ms pour vérifier _running régulièrement
            int poll_ret = poll(&pfd, 1, 500);
            
            if (poll_ret < 0) {
                if (errno == EINTR) continue; // Signal reçu
                fox::log::error("poll() failed: " + std::string(strerror(errno)));
                break;
            }
            
            if (poll_ret == 0) {
                // Timeout - on revérifie _running
                continue;
            }
            
            if (pfd.revents & POLLIN) {
                int rv = recv(_fd, _buffer.data(), _buffer.size(), MSG_DONTWAIT);
                if (rv > 0) {
                    nfq_handle_packet(_h, _buffer.data(), rv);
                } else if (rv < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    if (errno == EINTR) continue;
                    fox::log::error("recv() failed: " + std::string(strerror(errno)));
                    break;
                }
            }
        }
        
        fox::log::info("Shutting down gracefully...");
    }

    int NFQueue::callback(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg,
                          struct nfq_data* nfa, void* data) {
        
        uint32_t id = 0;
        struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
        if (ph) {
            id = ntohl(ph->packet_id);
        }

        unsigned char* raw_data = nullptr;
        int len = nfq_get_payload(nfa, &raw_data);

        uint32_t verdict = NF_ACCEPT;

        if (len > 0) {
            // Zero-Copy wrapper
            std::span<uint8_t> packet_span(reinterpret_cast<uint8_t*>(raw_data), len);
            fox::core::Packet pkt(packet_span);

            // Décision du moteur
            fox::Verdict v = fox::core::Engine::instance().process(pkt);

            if (v == fox::Verdict::DROP) {
                verdict = NF_DROP;
                if constexpr (fox::config::DEBUG_MODE) {
                    std::cout << "[NFQUEUE] Packet " << id << " -> NF_DROP" << std::endl;
                }
            }
        } else {
            if constexpr (fox::config::DEBUG_MODE) {
                std::cout << "[NFQUEUE] Packet " << id << " has no payload" << std::endl;
            }
        }

        return nfq_set_verdict(qh, id, verdict, 0, nullptr);
    }
}
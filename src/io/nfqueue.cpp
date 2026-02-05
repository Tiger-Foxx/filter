/**
 * nfqueue.cpp - Multi-Queue Multi-Thread NFQUEUE Handler
 * 
 * ARCHITECTURE MULTI-THREAD
 * =========================
 * 
 * ┌─────────────────────────────────────────────────────────────┐
 * │                     KERNEL (iptables)                       │
 * │  -j NFQUEUE --queue-balance 0:3                             │
 * │        │                                                     │
 * │   Hash(5-tuple) mod N                                        │
 * └────────┼─────────────────────────────────────────────────────┘
 *          │
 *    ┌─────┴─────┬─────────────┬─────────────┐
 *    ▼           ▼             ▼             ▼
 * Queue 0     Queue 1      Queue 2       Queue 3
 *    │           │             │             │
 *    ▼           ▼             ▼             ▼
 * Thread 0   Thread 1     Thread 2      Thread 3
 * [scratch]  [scratch]    [scratch]     [scratch]
 * [reassem]  [reassem]    [reassem]     [reassem]
 * 
 * Avantages:
 * - Chaque thread a ses propres ressources (pas de locks)
 * - Le kernel garantit que les paquets d'un même flux TCP 
 *   vont toujours à la même queue (hash sur 5-tuple)
 * - Scalabilité linéaire avec le nombre de cores
 */

#include "../../include/io/nfqueue.hpp"
#include "../../include/core/packet.hpp"
#include "../../include/core/types.hpp"
#include "../../include/core/flow_key.hpp"
#include "../../include/core/verdict.hpp"
#include "../../include/fastpath/rule_index.hpp"
#include "../../include/fastpath/port_map.hpp"
#include "../../include/deep/hs_matcher.hpp"
#include "../../include/deep/tcp_reassembler.hpp"
#include "../../include/utils/logger.hpp"
#include "../../include/config.hpp"

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnfnetlink/libnfnetlink.h>
#include <linux/netfilter.h>
#include <netinet/in.h>
#include <unistd.h>
#include <poll.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <algorithm>

namespace fox::io {

    // Structure étendue pour passer le contexte complet au callback
    struct CallbackContext {
        WorkerContext* worker;
        fox::fastpath::CompositeRuleIndex<fox::core::RuleDefinition>* index;
        fox::deep::HSMatcher* matcher;
    };

    // =========================================================================
    // PACKET PROCESSING (inline pour performance)
    // =========================================================================
    
    static inline fox::Verdict process_packet_inline(
        const fox::core::Packet& pkt,
        fox::fastpath::CompositeRuleIndex<fox::core::RuleDefinition>* index,
        fox::deep::HSMatcher* matcher,
        fox::deep::TcpReassembler* reassembler,
        hs_scratch_t* scratch)
    {
        if (!pkt.is_valid()) {
            return fox::Verdict::ACCEPT;
        }

        // NIVEAU 0.5 : Bypass flux déjà condamnés
        fox::core::FlowKey canonical_key;
        
        if (pkt.protocol() == IPPROTO_TCP) {
            canonical_key = fox::core::FlowKey(pkt.src_ip(), pkt.dst_ip(), 
                                                pkt.src_port(), pkt.dst_port());
            
            auto verdict = reassembler->get_flow_verdict(canonical_key);
            if (verdict == fox::deep::TcpStream::State::MALICIOUS) {
                reassembler->handle_lifecycle(canonical_key, pkt.is_fin(), pkt.is_rst());
                return fox::Verdict::DROP;
            }
        }

        // NIVEAU 1 : FastPath - Index Composite
        auto candidate_rules = index->lookup(pkt.src_ip(), pkt.dst_port());
        
        if (candidate_rules.empty()) {
            return fox::Verdict::ACCEPT;
        }

        // PHASE 1 : Scan Hyperscan (utilise le scratch du thread)
        std::vector<uint32_t> matched_hs_ids;
        matched_hs_ids.reserve(32);
        
        if (pkt.protocol() == IPPROTO_TCP) {
            bool already_malicious = reassembler->reassemble_and_scan(
                canonical_key, 
                pkt.src_ip(),
                pkt.tcp_seq(), 
                pkt.is_syn(), 
                pkt.is_fin(), 
                pkt.is_rst(), 
                pkt.payload(),
                matched_hs_ids
            );
            
            if (already_malicious) {
                return fox::Verdict::DROP;
            }
        } else {
            // UDP/ICMP: scan direct avec scratch du thread
            if (!pkt.payload().empty()) {
                matcher->scan_collect_all(pkt.payload().data(), pkt.payload().size(), 
                                          matched_hs_ids, scratch);
            }
        }

        // PHASE 2 : Vérification des règles
        for (const fox::core::RuleDefinition* rule : candidate_rules) {
            // Validation IP Destination
            if (!rule->optimized_dst_ips.empty()) {
                bool ip_match = false;
                uint32_t ip = pkt.dst_ip();
                for (const auto& cidr : rule->optimized_dst_ips) {
                    if ((ip & cidr.mask) == cidr.network) {
                        ip_match = true;
                        break;
                    }
                }
                if (!ip_match) continue;
            }
            
            if (!fox::fastpath::PortMatcher::match_src(pkt.src_port(), *rule)) {
                continue;
            }
            
            if (rule->get_proto_id() != 0 && rule->get_proto_id() != pkt.protocol()) {
                continue;
            }

            // NIVEAU 2 : Deep Path
            if (rule->hs_id == 0) continue;

            bool matched = false;
            
            if (rule->is_multi) {
                if (rule->is_or) {
                    for (uint32_t id : rule->atomic_ids) {
                        if (std::find(matched_hs_ids.begin(), matched_hs_ids.end(), id) 
                            != matched_hs_ids.end()) {
                            matched = true;
                            break;
                        }
                    }
                } else {
                    matched = true;
                    for (uint32_t id : rule->atomic_ids) {
                        if (std::find(matched_hs_ids.begin(), matched_hs_ids.end(), id) 
                            == matched_hs_ids.end()) {
                            matched = false;
                            break;
                        }
                    }
                }
            } else {
                matched = std::find(matched_hs_ids.begin(), matched_hs_ids.end(), rule->hs_id) 
                          != matched_hs_ids.end();
            }

            if (matched) {
                if (pkt.protocol() == IPPROTO_TCP) {
                    reassembler->mark_malicious(canonical_key);
                }
                return rule->get_verdict();
            }
        }
        
        return fox::Verdict::ACCEPT;
    }

    // =========================================================================
    // NFQUEUE CALLBACK
    // =========================================================================
    
    int NFQueueMulti::packet_callback(struct nfq_q_handle* qh, struct nfgenmsg* /*nfmsg*/,
                                       struct nfq_data* nfa, void* data) {
        CallbackContext* cb_ctx = static_cast<CallbackContext*>(data);
        WorkerContext* ctx = cb_ctx->worker;
        
        uint32_t id = 0;
        struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
        if (ph) {
            id = ntohl(ph->packet_id);
        }

        unsigned char* raw_data = nullptr;
        int len = nfq_get_payload(nfa, &raw_data);

        uint32_t verdict = NF_ACCEPT;

        if (len > 0) {
            std::span<uint8_t> packet_span(reinterpret_cast<uint8_t*>(raw_data), len);
            fox::core::Packet pkt(packet_span);

            fox::Verdict v = process_packet_inline(
                pkt,
                cb_ctx->index,
                cb_ctx->matcher,
                ctx->reassembler.get(),
                ctx->scratch
            );

            if (v == fox::Verdict::DROP) {
                verdict = NF_DROP;
                ctx->packets_dropped.fetch_add(1, std::memory_order_relaxed);
            }
        }
        
        ctx->packets_processed.fetch_add(1, std::memory_order_relaxed);
        return nfq_set_verdict(qh, id, verdict, 0, nullptr);
    }

    // =========================================================================
    // NFQueueMulti IMPLEMENTATION
    // =========================================================================

    NFQueueMulti::NFQueueMulti(uint16_t start_queue_id, uint32_t num_queues)
        : _start_queue_id(start_queue_id)
        , _num_queues(num_queues)
    {
    }

    NFQueueMulti::~NFQueueMulti() {
        stop();
        
        // Attendre que tous les threads se terminent
        for (auto& t : _threads) {
            if (t.joinable()) t.join();
        }
        
        // Cleanup des workers
        for (auto& ctx : _workers) {
            if (ctx) {
                if (ctx->qh) nfq_destroy_queue(ctx->qh);
                if (ctx->h) {
                    nfq_unbind_pf(ctx->h, AF_INET);
                    nfq_close(ctx->h);
                }
                if (ctx->scratch) hs_free_scratch(ctx->scratch);
            }
        }
        
        // Cleanup des callback contexts
        for (auto* cb : _callback_contexts) {
            delete cb;
        }
        
        fox::log::info("NFQUEUE resources released.");
    }

    bool NFQueueMulti::init(fox::fastpath::CompositeRuleIndex<fox::core::RuleDefinition>* index,
                            fox::deep::HSMatcher* matcher) {
        _index = index;
        _matcher = matcher;

        fox::log::info("Initializing " + std::to_string(_num_queues) + " NFQUEUE workers (Multi-Thread Mode)...");

        for (uint32_t i = 0; i < _num_queues; ++i) {
            auto ctx = std::make_unique<WorkerContext>();
            ctx->queue_id = _start_queue_id + i;
            ctx->buffer.resize(fox::config::MAX_PACKET_SIZE + 4096);

            // Allouer le scratch Hyperscan pour ce thread
            ctx->scratch = matcher->alloc_scratch_for_thread();
            if (!ctx->scratch) {
                fox::log::error("Failed to allocate Hyperscan scratch for worker " + std::to_string(i));
                return false;
            }

            // Créer le TcpReassembler pour ce thread avec son scratch dédié
            ctx->reassembler = std::make_unique<fox::deep::TcpReassembler>(matcher, ctx->scratch);

            // Ouvrir la queue NFQUEUE
            ctx->h = nfq_open();
            if (!ctx->h) {
                fox::log::error("nfq_open() failed for queue " + std::to_string(ctx->queue_id));
                return false;
            }

            nfq_unbind_pf(ctx->h, AF_INET);
            if (nfq_bind_pf(ctx->h, AF_INET) < 0) {
                fox::log::error("nfq_bind_pf() failed for queue " + std::to_string(ctx->queue_id));
                return false;
            }

            // Créer le contexte de callback avec toutes les références nécessaires
            auto* cb_ctx = new CallbackContext{ctx.get(), index, matcher};
            _callback_contexts.push_back(cb_ctx);

            ctx->qh = nfq_create_queue(ctx->h, ctx->queue_id, &NFQueueMulti::packet_callback, cb_ctx);
            if (!ctx->qh) {
                fox::log::error("nfq_create_queue() failed for queue " + std::to_string(ctx->queue_id));
                return false;
            }

            if (nfq_set_mode(ctx->qh, NFQNL_COPY_PACKET, fox::config::MAX_PACKET_SIZE) < 0) {
                fox::log::error("nfq_set_mode() failed for queue " + std::to_string(ctx->queue_id));
                return false;
            }

            nfnl_rcvbufsiz(nfq_nfnlh(ctx->h), fox::config::NETLINK_BUFFER_SIZE);
            ctx->fd = nfq_fd(ctx->h);

            _workers.push_back(std::move(ctx));
            fox::log::info("  Worker " + std::to_string(i) + " ready (Queue " + std::to_string(_start_queue_id + i) + ")");
        }

        return true;
    }

    void NFQueueMulti::worker_loop(WorkerContext* ctx) {
        struct pollfd pfd;
        pfd.fd = ctx->fd;
        pfd.events = POLLIN;

        while (_running.load(std::memory_order_relaxed)) {
            int poll_ret = poll(&pfd, 1, 100);  // 100ms timeout pour vérifier _running
            
            if (poll_ret < 0) {
                if (errno == EINTR) continue;
                break;
            }
            
            if (poll_ret == 0) continue;  // Timeout
            
            if (pfd.revents & POLLIN) {
                int rv = recv(ctx->fd, ctx->buffer.data(), ctx->buffer.size(), MSG_DONTWAIT);
                if (rv > 0) {
                    nfq_handle_packet(ctx->h, ctx->buffer.data(), rv);
                } else if (rv < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                    break;
                }
            }
        }
    }

    void NFQueueMulti::run() {
        _running.store(true, std::memory_order_release);
        
        fox::log::info(">>> Starting " + std::to_string(_num_queues) + " worker threads...");
        fox::log::info(">>> Configure iptables with: -j NFQUEUE --queue-balance " + 
                       std::to_string(_start_queue_id) + ":" + 
                       std::to_string(_start_queue_id + _num_queues - 1));
        fox::log::info(">>> Press CTRL+C to stop gracefully.");

        // Lancer tous les threads workers
        for (auto& ctx : _workers) {
            _threads.emplace_back(&NFQueueMulti::worker_loop, this, ctx.get());
        }

        // Thread de monitoring des stats (toutes les 5 secondes)
        std::thread stats_thread([this]() {
            uint64_t last_total = 0;
            auto last_time = std::chrono::steady_clock::now();
            
            while (_running.load(std::memory_order_relaxed)) {
                std::this_thread::sleep_for(std::chrono::seconds(5));
                if (!_running.load(std::memory_order_relaxed)) break;
                
                auto now = std::chrono::steady_clock::now();
                double elapsed = std::chrono::duration<double>(now - last_time).count();
                
                uint64_t current_total = total_packets();
                uint64_t delta = current_total - last_total;
                double pps = delta / elapsed;
                
                // Stats par thread
                std::string per_thread = "";
                for (size_t i = 0; i < _workers.size(); ++i) {
                    uint64_t pkts = _workers[i]->packets_processed.load(std::memory_order_relaxed);
                    per_thread += "T" + std::to_string(i) + ":" + std::to_string(pkts) + " ";
                }
                
                std::cout << "[STATS] " << std::fixed << std::setprecision(0) 
                          << pps << " pkt/s | Total: " << current_total 
                          << " | Drop: " << total_dropped()
                          << " | " << per_thread << std::endl;
                
                last_total = current_total;
                last_time = now;
            }
        });

        // Attendre tous les threads workers
        for (auto& t : _threads) {
            if (t.joinable()) {
                t.join();
            }
        }
        
        // Arrêter le thread de stats
        if (stats_thread.joinable()) {
            stats_thread.join();
        }
        
        // Afficher les stats finales
        fox::log::info("=== FINAL STATS ===");
        for (size_t i = 0; i < _workers.size(); ++i) {
            fox::log::info("  Thread " + std::to_string(i) + ": " + 
                          std::to_string(_workers[i]->packets_processed.load()) + " packets, " +
                          std::to_string(_workers[i]->packets_dropped.load()) + " dropped");
        }
        fox::log::info("Total: " + std::to_string(total_packets()) + " packets, " +
                       std::to_string(total_dropped()) + " dropped");
    }

    void NFQueueMulti::stop() {
        _running.store(false, std::memory_order_release);
    }

    uint64_t NFQueueMulti::total_packets() const {
        uint64_t total = 0;
        for (const auto& ctx : _workers) {
            total += ctx->packets_processed.load(std::memory_order_relaxed);
        }
        return total;
    }

    uint64_t NFQueueMulti::total_dropped() const {
        uint64_t total = 0;
        for (const auto& ctx : _workers) {
            total += ctx->packets_dropped.load(std::memory_order_relaxed);
        }
        return total;
    }

}
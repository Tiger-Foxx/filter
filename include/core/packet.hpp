#ifndef FOX_CORE_PACKET_HPP
#define FOX_CORE_PACKET_HPP

#include <cstdint>
#include <span>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

namespace fox::core {

    /**
     * Wrapper Zero-Copy autour d'un buffer réseau brut.
     * Ne copie rien, pointe juste vers les headers et le payload.
     */
    class Packet {
    public:
        explicit Packet(std::span<uint8_t> raw_data) : _data(raw_data) {
            parse();
        }

        bool is_valid() const { return _ip_header != nullptr; }

        // --- Layer 3 (IP) ---
        uint8_t protocol() const { return _ip_header ? _ip_header->protocol : 0; }
        uint32_t src_ip() const { return _ip_header ? ntohl(_ip_header->saddr) : 0; }
        uint32_t dst_ip() const { return _ip_header ? ntohl(_ip_header->daddr) : 0; }

        // --- Layer 4 (Ports) ---
        uint16_t src_port() const {
            if (_tcp_header) return ntohs(_tcp_header->source);
            if (_udp_header) return ntohs(_udp_header->source);
            return 0;
        }
        uint16_t dst_port() const {
            if (_tcp_header) return ntohs(_tcp_header->dest);
            if (_udp_header) return ntohs(_udp_header->dest);
            return 0;
        }

        // --- Layer 4 (TCP Flags & Seq) ---
        // Retourne 0/false si ce n'est pas du TCP
        uint32_t tcp_seq() const { return _tcp_header ? ntohl(_tcp_header->seq) : 0; }
        uint32_t tcp_ack() const { return _tcp_header ? ntohl(_tcp_header->ack_seq) : 0; }
        bool is_syn() const { return _tcp_header ? _tcp_header->syn : false; }
        bool is_fin() const { return _tcp_header ? _tcp_header->fin : false; }
        bool is_rst() const { return _tcp_header ? _tcp_header->rst : false; }
        bool is_ack() const { return _tcp_header ? _tcp_header->ack : false; }
        bool is_psh() const { return _tcp_header ? _tcp_header->psh : false; }

        // --- Payload ---
        std::span<const uint8_t> payload() const {
            if (!_payload_ptr) return {};
            return { _payload_ptr, _payload_len };
        }

    private:
        std::span<uint8_t> _data;
        struct iphdr* _ip_header = nullptr;
        struct tcphdr* _tcp_header = nullptr;
        struct udphdr* _udp_header = nullptr;
        
        const uint8_t* _payload_ptr = nullptr;
        size_t _payload_len = 0;

        void parse() {
            if (_data.size() < sizeof(struct iphdr)) return;
            
            _ip_header = reinterpret_cast<struct iphdr*>(_data.data());
            size_t ip_len = _ip_header->ihl * 4;
            
            if (_data.size() < ip_len) { _ip_header = nullptr; return; }

            uint8_t* l4_ptr = _data.data() + ip_len;
            size_t remaining_len = _data.size() - ip_len;

            if (_ip_header->protocol == IPPROTO_TCP) {
                if (remaining_len < sizeof(struct tcphdr)) return;
                _tcp_header = reinterpret_cast<struct tcphdr*>(l4_ptr);
                
                size_t tcp_len = _tcp_header->doff * 4;
                if (remaining_len < tcp_len) { _tcp_header = nullptr; return; }
                
                _payload_ptr = l4_ptr + tcp_len;
                _payload_len = remaining_len - tcp_len;

            } else if (_ip_header->protocol == IPPROTO_UDP) {
                if (remaining_len < sizeof(struct udphdr)) return;
                _udp_header = reinterpret_cast<struct udphdr*>(l4_ptr);
                
                size_t udp_len = sizeof(struct udphdr);
                _payload_ptr = l4_ptr + udp_len;
                _payload_len = remaining_len - udp_len;
            }
        }
    };
}

#endif // FOX_CORE_PACKET_HPP
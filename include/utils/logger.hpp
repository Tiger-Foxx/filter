#ifndef FOX_LOGGER_HPP
#define FOX_LOGGER_HPP

#include <iostream>
#include <string_view>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include "../config.hpp"

namespace fox::log {

    // Critical log: Always displayed (stderr)
    inline void error(std::string_view msg) {
        std::cerr << "[CRITICAL] " << msg << std::endl;
    }

    // Info log: For major milestones
    inline void info(std::string_view msg) {
        std::cout << "[INFO] " << msg << std::endl;
    }

    // Debug log: Controlled by DEBUG_MODE in config.hpp
    inline void debug(std::string_view msg) {
        if constexpr (fox::config::DEBUG_MODE) {
            std::cout << "[DEBUG] " << msg << std::endl;
        }
    }

    // Packet log: Displays packet details (if DEBUG_MODE active)
    inline void packet(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, 
                       uint8_t proto, size_t payload_len, std::string_view extra = "") {
        if constexpr (fox::config::DEBUG_MODE) {
            std::ostringstream oss;
            oss << "[PKT] "
                << ((src_ip >> 24) & 0xFF) << "." << ((src_ip >> 16) & 0xFF) << "."
                << ((src_ip >> 8) & 0xFF) << "." << (src_ip & 0xFF)
                << ":" << src_port << " -> "
                << ((dst_ip >> 24) & 0xFF) << "." << ((dst_ip >> 16) & 0xFF) << "."
                << ((dst_ip >> 8) & 0xFF) << "." << (dst_ip & 0xFF)
                << ":" << dst_port
                << " proto=" << (int)proto
                << " len=" << payload_len;
            if (!extra.empty()) oss << " " << extra;
            std::cout << oss.str() << std::endl;
        }
    }

    // Verdict log: Displays the decision taken
    inline void verdict(const char* decision, uint32_t rule_id = 0, uint32_t hs_id = 0) {
        if constexpr (fox::config::DEBUG_MODE) {
            std::ostringstream oss;
            oss << "[VERDICT] " << decision;
            if (rule_id > 0) oss << " rule=" << rule_id;
            if (hs_id > 0) oss << " hs_id=" << hs_id;
            std::cout << oss.str() << std::endl;
        }
    }

    // Hex payload log (hex dump of first bytes)
    inline void payload_hex(const uint8_t* data, size_t len, size_t max_bytes = 64) {
        if constexpr (fox::config::DEBUG_MODE) {
            if (!data || len == 0) return;
            size_t to_print = std::min(len, max_bytes);
            std::ostringstream oss;
            oss << "[PAYLOAD] first " << to_print << " bytes: ";
            for (size_t i = 0; i < to_print; ++i) {
                oss << std::hex << std::setfill('0') << std::setw(2) << (int)data[i];
                if (i < to_print - 1) oss << " ";
            }
            if (len > max_bytes) oss << " ...";
            std::cout << oss.str() << std::endl;
        }
    }

    // ASCII payload log (printable characters)
    inline void payload_ascii(const uint8_t* data, size_t len, size_t max_bytes = 128) {
        if constexpr (fox::config::DEBUG_MODE) {
            if (!data || len == 0) return;
            size_t to_print = std::min(len, max_bytes);
            std::ostringstream oss;
            oss << "[PAYLOAD_ASCII] \"";
            for (size_t i = 0; i < to_print; ++i) {
                char c = static_cast<char>(data[i]);
                if (c >= 32 && c < 127) oss << c;
                else oss << ".";
            }
            oss << "\"";
            if (len > max_bytes) oss << " ...";
            std::cout << oss.str() << std::endl;
        }
    }

    // Hyperscan match log
    inline void hs_match(uint32_t hs_id, bool matched) {
        if constexpr (fox::config::DEBUG_MODE) {
            std::cout << "[HS] scan hs_id=" << hs_id << " -> " << (matched ? "MATCH" : "no match") << std::endl;
        }
    }

    //Log reassembly
    inline void reassembly(const char* action, size_t data_len = 0) {
        if constexpr (fox::config::DEBUG_MODE) {
            std::ostringstream oss;
            oss << "[REASSEMBLY] " << action;
            if (data_len > 0) oss << " (" << data_len << " bytes)";
            std::cout << oss.str() << std::endl;
        }
    }
}

#endif //FOX_LOGGER_HPP
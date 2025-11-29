#include "../../include/deep/hs_matcher.hpp"
#include "../../include/utils/logger.hpp"
#include <fstream>
#include <vector>
#include <iostream>

namespace fox::deep {

    HSMatcher::~HSMatcher() {
        if (scratch) hs_free_scratch(scratch);
        if (db) hs_free_database(db);
    }

    unsigned int HSMatcher::parse_flags(const std::string& flags_str) {
        unsigned int flags = HS_FLAG_DOTALL; 
        for (char c : flags_str) {
            if (c == 'i') flags |= HS_FLAG_CASELESS;
            if (c == 'm') flags |= HS_FLAG_MULTILINE;
            if (c == 's') flags |= HS_FLAG_DOTALL;
        }
        return flags;
    }

    bool HSMatcher::init(const std::string& patterns_path) {
        fox::log::info("Loading Hyperscan patterns from: " + patterns_path);

        std::ifstream infile(patterns_path);
        if (!infile.good()) return false;

        std::vector<const char*> expressions;
        std::vector<unsigned int> flags;
        std::vector<unsigned int> ids;
        std::vector<std::string> storage; // Garde les strings en mémoire

        std::string line;
        while (std::getline(infile, line)) {
            if (line.empty() || line[0] == '#') continue;

            size_t c1 = line.find(':');
            size_t s1 = line.find('/');
            size_t s2 = line.rfind('/');

            if (c1 == std::string::npos || s1 == std::string::npos || s2 == std::string::npos) continue;

            try {
                unsigned int id = std::stoul(line.substr(0, c1));
                std::string regex = line.substr(s1 + 1, s2 - s1 - 1);
                std::string f_str = line.substr(s2 + 1);

                storage.push_back(regex);
                expressions.push_back(storage.back().c_str());
                flags.push_back(parse_flags(f_str));
                ids.push_back(id);
            } catch (...) { continue; }
        }

        if (expressions.empty()) {
            fox::log::info("No patterns found.");
            return true;
        }

        // IMPORTANT : HS_MODE_STREAM pour supporter le TCP Reassembly
        hs_compile_error_t* err;
        if (hs_compile_multi(expressions.data(), flags.data(), ids.data(), 
                             expressions.size(), HS_MODE_STREAM, nullptr, &db, &err) != HS_SUCCESS) {
            fox::log::error(std::string("HS Compile failed: ") + err->message);
            hs_free_compile_error(err);
            return false;
        }

        if (hs_alloc_scratch(db, &scratch) != HS_SUCCESS) return false;
        
        fox::log::info("Hyperscan compiled " + std::to_string(expressions.size()) + " patterns (Streaming Mode).");
        return true;
    }

    // Callback unique utilisé pour stopper le scan dès qu'on trouve l'ID cible
    static int match_handler(unsigned int id, unsigned long long, unsigned long long, unsigned int, void* ctx) {
        uint32_t target = *static_cast<uint32_t*>(ctx);
        return (id == target) ? HS_SCAN_TERMINATED : 0;
    }

    bool HSMatcher::scan_block(std::span<const uint8_t> payload, uint32_t target_id) const {
        if (!db || !scratch) return false;
        uint32_t ctx = target_id;
        // En mode Stream, on peut utiliser hs_scan_stream sur un block unique via un stream temporaire,
        // ou utiliser hs_scan() si la DB a été compilée en BLOCK. 
        // ATTENTION : Une DB STREAM ne supporte PAS hs_scan() standard.
        // Il faut utiliser l'API Stream même pour un block unique.
        
        hs_stream_t* stream = nullptr;
        hs_error_t err = hs_open_stream(db, 0, &stream);
        if (err != HS_SUCCESS) return false;

        err = hs_scan_stream(stream, reinterpret_cast<const char*>(payload.data()), payload.size(), 0, scratch, match_handler, &ctx);
        hs_close_stream(stream, scratch, nullptr, nullptr);
        
        return (err == HS_SCAN_TERMINATED);
    }

    hs_stream_t* HSMatcher::open_stream() {
        hs_stream_t* stream = nullptr;
        hs_open_stream(db, 0, &stream);
        return stream;
    }

    bool HSMatcher::scan_stream(hs_stream_t* stream, std::span<const uint8_t> data, uint32_t target_id) {
        if (!stream || !scratch) return false;
        uint32_t ctx = target_id;
        hs_error_t err = hs_scan_stream(stream, reinterpret_cast<const char*>(data.data()), data.size(), 0, scratch, match_handler, &ctx);
        return (err == HS_SCAN_TERMINATED);
    }

    void HSMatcher::close_stream(hs_stream_t* stream) {
        if (stream && scratch) {
            hs_close_stream(stream, scratch, nullptr, nullptr);
        }
    }
}
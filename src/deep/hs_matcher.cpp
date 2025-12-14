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

    /**
     * Parse les flags du format patterns.txt vers les flags Hyperscan.
     * 
     * Flags supportés:
     * - 'i' : HS_FLAG_CASELESS (case-insensitive)
     * - 'm' : HS_FLAG_MULTILINE (^ et $ matchent les lignes)
     * - 's' : HS_FLAG_DOTALL (. matche aussi \n)
     * - 'H' : HS_FLAG_SINGLEMATCH (un seul match par pattern)
     * - 'c' : HS_FLAG_COMBINATION (logique combinatoire AND/OR)
     */
    unsigned int HSMatcher::parse_flags(const std::string& flags_str) {
        unsigned int flags = 0;
        bool has_combination = false;

        for (char c : flags_str) {
            switch (c) {
                case 'i': flags |= HS_FLAG_CASELESS; break;
                case 'm': flags |= HS_FLAG_MULTILINE; break;
                case 's': flags |= HS_FLAG_DOTALL; break;
                case 'H': flags |= HS_FLAG_SINGLEMATCH; break;
                case 'c':
                    flags |= HS_FLAG_COMBINATION;
                    has_combination = true;
                    break;
            }
        }

        // Les expressions combinatoires sont des zéros-longueur logiques :
        // on autorise explicitement l'empty-match pour éviter l'échec de compilation.
        if (has_combination) {
            flags |= HS_FLAG_ALLOWEMPTY;
        }

        // Si pas de flags spécifiés et pas combinatoire, ajouter DOTALL par défaut
        if (flags == 0) {
            flags = HS_FLAG_DOTALL;
        }

        return flags;
    }

    bool HSMatcher::init(const std::string& patterns_path) {
        fox::log::info("Loading Hyperscan patterns from: " + patterns_path);

        std::ifstream infile(patterns_path);
        if (!infile.good()) {
            fox::log::error("Cannot open patterns file: " + patterns_path);
            return false;
        }

        // On stocke d'abord toutes les chaînes pour garantir la stabilité mémoire,
        // puis on prendra les c_str() après la boucle (évite les pointeurs invalides
        // dus aux réallocations de vector pendant le push_back).
        std::vector<std::string> storage;
        std::vector<unsigned int> flags;
        std::vector<unsigned int> ids;
        std::vector<const char*> expressions;

        std::string line;
        int line_num = 0;
        while (std::getline(infile, line)) {
            line_num++;
            if (line.empty() || line[0] == '#') continue;

            size_t c1 = line.find(':');
            size_t s1 = line.find('/');
            size_t s2 = line.rfind('/');

            if (c1 == std::string::npos || s1 == std::string::npos || s2 == std::string::npos || s1 >= s2) {
                fox::log::debug("Skipping malformed line " + std::to_string(line_num));
                continue;
            }

            try {
                unsigned int id = std::stoul(line.substr(0, c1));
                std::string regex = line.substr(s1 + 1, s2 - s1 - 1);
                std::string f_str = line.substr(s2 + 1);

                // Skip les patterns vides
                if (regex.empty()) {
                    fox::log::debug("Skipping empty pattern at line " + std::to_string(line_num));
                    continue;
                }

                storage.push_back(regex);
                flags.push_back(parse_flags(f_str));
                ids.push_back(id);
                
                fox::log::debug("Loaded pattern ID=" + std::to_string(id) + 
                               " flags=0x" + std::to_string(flags.back()) +
                               " regex=" + regex.substr(0, 50) + (regex.size() > 50 ? "..." : ""));
                               
            } catch (const std::exception& e) { 
                fox::log::debug("Parse error line " + std::to_string(line_num) + ": " + e.what());
                continue; 
            }
        }

        if (storage.empty()) {
            fox::log::info("No patterns found in file.");
            return true; // Pas une erreur fatale
        }

        // Maintenant que storage ne bougera plus, on peut référencer les c_str()
        expressions.reserve(storage.size());
        for (const auto& s : storage) {
            expressions.push_back(s.c_str());
        }

        // IMPORTANT : HS_MODE_STREAM pour supporter le TCP Reassembly
        hs_compile_error_t* err;
        hs_error_t compile_result = hs_compile_multi(
            expressions.data(), 
            flags.data(), 
            ids.data(), 
            expressions.size(), 
            HS_MODE_STREAM, 
            nullptr, 
            &db, 
            &err
        );
        
        if (compile_result != HS_SUCCESS) {
            std::string err_msg = err ? err->message : "Unknown error";
            int err_expr = err ? err->expression : -1;
            
            fox::log::error("HS Compile failed: " + err_msg);
            if (err_expr >= 0 && err_expr < (int)storage.size()) {
                fox::log::error("Problematic pattern ID=" + std::to_string(ids[err_expr]) + 
                               " : " + storage[err_expr]);
            }
            
            if (err) hs_free_compile_error(err);
            return false;
        }

        if (hs_alloc_scratch(db, &scratch) != HS_SUCCESS) {
            fox::log::error("Failed to allocate Hyperscan scratch space");
            return false;
        }
        
        fox::log::info("Hyperscan compiled " + std::to_string(expressions.size()) + " patterns (Streaming Mode).");
        return true;
    }

    // Callback unique utilisé pour stopper le scan dès qu'on trouve l'ID cible
    static int match_handler(unsigned int id, unsigned long long, unsigned long long, unsigned int, void* ctx) {
        uint32_t target = *static_cast<uint32_t*>(ctx);
        // Si l'ID trouvé est celui qu'on cherche, on arrête le scan
        // Note: Pour les expressions combinatoires, Hyperscan déclenche le callback
        // UNIQUEMENT quand toute l'expression logique est satisfaite
        return (id == target) ? HS_SCAN_TERMINATED : 0;
    }

    bool HSMatcher::scan_block(std::span<const uint8_t> payload, uint32_t target_id) const {
        if (!db || !scratch) return false;
        uint32_t ctx = target_id;
        
        // En mode STREAM, on doit utiliser l'API Stream même pour un block unique
        // car hs_scan() n'est pas supporté sur une DB compilée en STREAM
        
        hs_stream_t* stream = nullptr;
        hs_error_t err = hs_open_stream(db, 0, &stream);
        if (err != HS_SUCCESS) return false;

        err = hs_scan_stream(stream, reinterpret_cast<const char*>(payload.data()), payload.size(), 0, scratch, match_handler, &ctx);
        hs_close_stream(stream, scratch, nullptr, nullptr);
        
        return (err == HS_SCAN_TERMINATED);
    }

    hs_stream_t* HSMatcher::open_stream() {
        if (!db) return nullptr;
        hs_stream_t* stream = nullptr;
        hs_error_t err = hs_open_stream(db, 0, &stream);
        if (err != HS_SUCCESS) {
            fox::log::debug("Failed to open Hyperscan stream");
            return nullptr;
        }
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
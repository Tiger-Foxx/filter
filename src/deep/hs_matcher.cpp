/**
 * hs_matcher.cpp - Hyperscan Multi-Pattern Matcher (BLOCK MODE)
 */

#include "../../include/deep/hs_matcher.hpp"
#include "../../include/utils/logger.hpp"
#include <fstream>
#include <vector>
#include <iostream>

namespace fox::deep {

    HSMatcher::~HSMatcher() {
        if (scratch_) hs_free_scratch(scratch_);
        if (db_) hs_free_database(db_);
    }

    /**
     * Parses flags from patterns.txt format to Hyperscan flags.
     * 
     * Supported flags:
     * - 'i' : HS_FLAG_CASELESS (case-insensitive)
     * - 'm' : HS_FLAG_MULTILINE (^ and $ match lines)
     * - 's' : HS_FLAG_DOTALL (. also matches \n)
     * - 'H' : HS_FLAG_SINGLEMATCH (only one match per pattern)
     */
    unsigned int HSMatcher::parse_flags(const std::string& flags_str) {
        unsigned int flags = 0;

        for (char c : flags_str) {
            switch (c) {
                case 'i': flags |= HS_FLAG_CASELESS; break;
                case 'm': flags |= HS_FLAG_MULTILINE; break;
                case 's': flags |= HS_FLAG_DOTALL; break;
                case 'H': flags |= HS_FLAG_SINGLEMATCH; break;
                // 'c' (combination) is ignored - we skip these patterns
            }
        }

        // Default to DOTALL if no flags specified
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

        // Store strings first to ensure memory stability before taking c_str() pointers.
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

                // Skip empty patterns
                if (regex.empty()) {
                    fox::log::debug("Skipping empty pattern at line " + std::to_string(line_num));
                    continue;
                }

                // IMPORTANT: Skip combinatorial expressions (flag 'c')
                // We ONLY compile atomic patterns. 
                // AND/OR logic is handled in C++ after scanning.
                if (f_str.find('c') != std::string::npos) {
                    continue;
                }

                storage.push_back(regex);
                flags.push_back(parse_flags(f_str));
                ids.push_back(id);
                               
            } catch (const std::exception& e) { 
                fox::log::debug("Parse error line " + std::to_string(line_num) + ": " + e.what());
                continue; 
            }
        }

        if (storage.empty()) {
            fox::log::info("No patterns found in file.");
            return true; //Pas une erreur fatale
        }

        //Maintenant que storage ne bougera plus, on peut référencer les c_str()
        expressions.reserve(storage.size());
        for (const auto& s : storage) {
            expressions.push_back(s.c_str());
        }

       
        //CHANGEMENT CRITIQUE : HS_MODE_BLOCK au lieu de HS_MODE_STREAM
       
        //Suricata utilise exclusivement HS_MODE_BLOCK pour le MPM.
        //C'est 10-100x plus rapide que le mode STREAM.
        //Le réassemblage TCP se fait AVANT le scan, pas pendant.
       
        hs_compile_error_t* err = nullptr;
        hs_error_t compile_result = hs_compile_multi(
            expressions.data(), 
            flags.data(), 
            ids.data(), 
            static_cast<unsigned int>(expressions.size()), 
            HS_MODE_BLOCK,  //<-- CRITIQUE : BLOCK au lieu de STREAM
            nullptr, 
            &db_, 
            &err
        );
        
        if (compile_result != HS_SUCCESS) {
            std::string err_msg = err ? err->message : "Unknown error";
            int err_expr = err ? err->expression : -1;
            
            fox::log::error("HS Compile failed: " + err_msg);
            if (err_expr >= 0 && err_expr < static_cast<int>(storage.size())) {
                fox::log::error("Problematic pattern ID=" + std::to_string(ids[err_expr]) + 
                               " : " + storage[err_expr]);
            }
            
            if (err) hs_free_compile_error(err);
            return false;
        }

        if (hs_alloc_scratch(db_, &scratch_) != HS_SUCCESS) {
            fox::log::error("Failed to allocate Hyperscan scratch space");
            return false;
        }
        
        pattern_count_ = expressions.size();
        fox::log::info("Hyperscan compiled " + std::to_string(pattern_count_) + 
                       " patterns (BLOCK Mode - Multi-Thread Ready)");
        return true;
    }

   
    //MULTI-THREAD SUPPORT
   
    
    hs_scratch_t* HSMatcher::alloc_scratch_for_thread() const {
        if (!db_) return nullptr;
        
        hs_scratch_t* thread_scratch = nullptr;
        if (hs_alloc_scratch(db_, &thread_scratch) != HS_SUCCESS) {
            return nullptr;
        }
        return thread_scratch;
    }

   
    //CALLBACKS HYPERSCAN
   

    //Callback qui retourne true dès le premier match (pour scan rapide)
    static int match_any_callback(unsigned int /*id*/, 
                                   unsigned long long /*from*/, 
                                   unsigned long long /*to*/, 
                                   unsigned int /*flags*/, 
                                   void* ctx) {
        bool* found = static_cast<bool*>(ctx);
        *found = true;
        return 1;  //Stop scan immédiatement
    }

    //Callback qui collecte tous les IDs matchés (pour scan complet)
    static int match_collect_callback(unsigned int id, 
                                       unsigned long long /*from*/, 
                                       unsigned long long /*to*/, 
                                       unsigned int /*flags*/, 
                                       void* ctx) {
        std::vector<uint32_t>* matched = static_cast<std::vector<uint32_t>*>(ctx);
        matched->push_back(id);
        return 0;  //Continuer le scan
    }

   
    //API THREAD-SAFE (avec scratch fourni)
   

    bool HSMatcher::scan(const uint8_t* data, size_t len, hs_scratch_t* scratch) const {
        if (!db_ || !scratch || !data || len == 0) return false;
        
        bool found = false;
        hs_error_t err = hs_scan(
            db_,
            reinterpret_cast<const char*>(data),
            static_cast<unsigned int>(len),
            0,
            scratch,
            match_any_callback,
            &found
        );
        
        return found || (err == HS_SCAN_TERMINATED);
    }

    bool HSMatcher::scan_collect_all(const uint8_t* data, size_t len, 
                                      std::vector<uint32_t>& matched_ids,
                                      hs_scratch_t* scratch) const {
        matched_ids.clear();
        if (!db_ || !scratch || !data || len == 0) return false;
        
        matched_ids.reserve(32);
        hs_scan(
            db_,
            reinterpret_cast<const char*>(data),
            static_cast<unsigned int>(len),
            0,
            scratch,
            match_collect_callback,
            &matched_ids
        );
        
        return !matched_ids.empty();
    }

   
    //API LEGACY (mono-thread, utilise scratch_ interne)
   

    bool HSMatcher::scan(const uint8_t* data, size_t len) const {
        return scan(data, len, scratch_);
    }

    bool HSMatcher::scan_collect_all(const uint8_t* data, size_t len, 
                                      std::vector<uint32_t>& matched_ids) const {
        return scan_collect_all(data, len, matched_ids, scratch_);
    }

}
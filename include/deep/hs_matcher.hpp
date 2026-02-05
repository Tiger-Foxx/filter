#ifndef FOX_DEEP_HS_MATCHER_HPP
#define FOX_DEEP_HS_MATCHER_HPP

/**
 * HSMatcher - Moteur Hyperscan Multi-Thread (Mode BLOCK)
 * 
 * ARCHITECTURE MULTI-THREAD
 * =========================
 * 
 * Hyperscan requiert un "scratch space" par thread concurrent.
 * La DB est thread-safe et partagée, mais le scratch ne l'est pas.
 * 
 * Solution:
 * - Une seule DB compilée (partagée, read-only)
 * - Un scratch par thread (alloué via alloc_scratch_for_thread)
 * - Chaque worker appelle scan() avec son propre scratch
 */

#include <cstdint>
#include <string>
#include <vector>
#include <mutex>
#include <hs/hs.h>

namespace fox::deep {

    class HSMatcher {
    public:
        HSMatcher() = default;
        ~HSMatcher();

        // Interdiction de copie
        HSMatcher(const HSMatcher&) = delete;
        HSMatcher& operator=(const HSMatcher&) = delete;

        /**
         * Charge et compile la DB Hyperscan (thread-safe, appelé une seule fois)
         */
        bool init(const std::string& patterns_path);

        /**
         * Alloue un scratch space pour un thread worker.
         * DOIT être appelé par chaque thread AVANT d'utiliser scan().
         * Le scratch retourné appartient à l'appelant qui doit le libérer.
         * 
         * @return Scratch space pour ce thread, ou nullptr si erreur
         */
        hs_scratch_t* alloc_scratch_for_thread() const;

        /**
         * Scan avec scratch fourni (THREAD-SAFE)
         * Chaque thread utilise son propre scratch.
         */
        bool scan(const uint8_t* data, size_t len, hs_scratch_t* scratch) const;

        /**
         * Scan et collecte tous les IDs (THREAD-SAFE)
         */
        bool scan_collect_all(const uint8_t* data, size_t len,
                              std::vector<uint32_t>& matched_ids,
                              hs_scratch_t* scratch) const;

        /**
         * Versions legacy (utilisent le scratch interne - NON THREAD-SAFE)
         * Gardées pour compatibilité mono-thread
         */
        bool scan(const uint8_t* data, size_t len) const;
        bool scan_collect_all(const uint8_t* data, size_t len,
                              std::vector<uint32_t>& matched_ids) const;

        uint32_t pattern_count() const { return pattern_count_; }
        bool is_ready() const { return db_ != nullptr; }

    private:
        hs_database_t* db_ = nullptr;
        hs_scratch_t* scratch_ = nullptr;  // Scratch legacy pour mono-thread
        uint32_t pattern_count_ = 0;

        static unsigned int parse_flags(const std::string& flags_str);
    };

}

#endif // FOX_DEEP_HS_MATCHER_HPP
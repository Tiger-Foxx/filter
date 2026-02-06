#ifndef FOX_DEEP_HS_MATCHER_HPP
#define FOX_DEEP_HS_MATCHER_HPP

/**
 * HSMatcher - Multi-Threaded Hyperscan Engine (BLOCK Mode)
 * 
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

        // Copy prevention
        HSMatcher(const HSMatcher&) = delete;
        HSMatcher& operator=(const HSMatcher&) = delete;

        /**
         * Loads and compiles the Hyperscan database (thread-safe, called once)
         */
        bool init(const std::string& patterns_path);

        /**
         * Allocates a scratch space for a worker thread.
         * MUST be called by each thread BEFORE using scan().
         * Caller is responsible for the returned scratch space.
         * 
         * @return Scratch space for this thread, or nullptr if error
         */
        hs_scratch_t* alloc_scratch_for_thread() const;

        /**
         * Scan with provided scratch (THREAD-SAFE)
         * Each thread uses its own scratch space.
         */
        bool scan(const uint8_t* data, size_t len, hs_scratch_t* scratch) const;

        /**
         * Scan and collect all IDs (THREAD-SAFE)
         */
        bool scan_collect_all(const uint8_t* data, size_t len,
                              std::vector<uint32_t>& matched_ids,
                              hs_scratch_t* scratch) const;

        /**
         * Legacy versions (using internal scratch - NOT THREAD-SAFE)
         * Kept for single-threaded compatibility
         */
        bool scan(const uint8_t* data, size_t len) const;
        bool scan_collect_all(const uint8_t* data, size_t len,
                              std::vector<uint32_t>& matched_ids) const;

        uint32_t pattern_count() const { return pattern_count_; }
        bool is_ready() const { return db_ != nullptr; }

    private:
        hs_database_t* db_ = nullptr;
        hs_scratch_t* scratch_ = nullptr;  // Legacy scratch for single-thread
        uint32_t pattern_count_ = 0;

        static unsigned int parse_flags(const std::string& flags_str);
    };

}

#endif //FOX_DEEP_HS_MATCHER_HPP
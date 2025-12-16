#ifndef FOX_DEEP_HS_MATCHER_HPP
#define FOX_DEEP_HS_MATCHER_HPP

#include <string>
#include <vector>
#include <span>
#include <set>
#include <hs/hs.h>

namespace fox::deep {

    class HSMatcher {
    public:
        HSMatcher() = default;
        ~HSMatcher();

        // Interdiction de copie (HS Database est un pointeur opaque unique)
        HSMatcher(const HSMatcher&) = delete;
        HSMatcher& operator=(const HSMatcher&) = delete;

        /**
         * Charge le fichier patterns.txt, parse les regex/flags et compile la DB.
         * Format ligne: ID:/regex/flags
         */
        bool init(const std::string& patterns_path);

        /**
         * Scan un payload brut en mode Block (UDP/ICMP).
         * @param payload Données du paquet (Zero-Copy via std::span)
         * @param target_id L'ID de pattern attendu par la règle IP (trouvé via FastPath).
         * @return true si le pattern target_id est trouvé.
         */
        bool scan_block(std::span<const uint8_t> payload, uint32_t target_id) const;
        
        /**
         * NOUVEAU: Scan multi-pattern pour règles avec logique AND/OR.
         * Implémenté car HS_FLAG_COMBINATION n'est PAS supporté en HS_MODE_STREAM.
         * 
         * @param payload Données du paquet
         * @param atomic_ids Liste des IDs atomiques à vérifier
         * @param is_or True=OR (un match suffit), False=AND (tous doivent matcher)
         * @return true si la logique est satisfaite
         */
        bool scan_block_multi(std::span<const uint8_t> payload, 
                              const std::vector<uint32_t>& atomic_ids, 
                              bool is_or) const;

        /**
         * Ouvre un stream Hyperscan pour le mode TCP Reassembly.
         * @return Pointeur vers le stream HS ou nullptr en cas d'échec.
         */
        hs_stream_t* open_stream();

        /**
         * Scan incrémental sur un stream TCP.
         * @param stream Le contexte stream HS ouvert via open_stream()
         * @param data Données réassemblées à scanner
         * @param target_id L'ID de pattern cible
         * @return true si le pattern est trouvé
         */
        bool scan_stream(hs_stream_t* stream, std::span<const uint8_t> data, uint32_t target_id);
        
        /**
         * NOUVEAU: Scan incrémental multi-pattern pour TCP avec logique AND/OR.
         * 
         * @param stream Le contexte stream HS
         * @param data Données réassemblées
         * @param atomic_ids Liste des IDs atomiques à vérifier
         * @param is_or True=OR, False=AND
         * @return true si la logique est satisfaite
         */
        bool scan_stream_multi(hs_stream_t* stream, 
                               std::span<const uint8_t> data, 
                               const std::vector<uint32_t>& atomic_ids, 
                               bool is_or);

        /**
         * Ferme et libère un stream Hyperscan.
         * @param stream Le contexte stream à fermer
         */
        void close_stream(hs_stream_t* stream);

    private:
        hs_database_t* db = nullptr;
        hs_scratch_t* scratch = nullptr;

        // Helper pour convertir "im" -> HS_FLAG_CASELESS | HS_FLAG_MULTILINE
        static unsigned int parse_flags(const std::string& flags_str);
    };

}

#endif // FOX_DEEP_HS_MATCHER_HPP
#ifndef FOX_DEEP_HS_MATCHER_HPP
#define FOX_DEEP_HS_MATCHER_HPP

/**
 * HSMatcher - Moteur Hyperscan optimisé pour le filtrage haute performance
 * 
 * ARCHITECTURE OPTIMISÉE (Mode BLOCK comme Suricata)
 * ==================================================
 * 
 * AVANT (Mode STREAM - LENT) :
 * - hs_open_stream() pour chaque connexion TCP
 * - hs_scan_stream() incrémental
 * - hs_close_stream() à la fin
 * - Problème : Accumulation de streams, overhead énorme
 * 
 * MAINTENANT (Mode BLOCK - RAPIDE) :
 * - Une seule DB compilée en HS_MODE_BLOCK
 * - Le réassemblage TCP se fait AVANT le scan (dans TcpStream)
 * - hs_scan() direct sur le buffer complet
 * - Pas de streams à maintenir, pas d'accumulation
 * 
 * PERFORMANCE : ~10-100x plus rapide que le mode STREAM
 */

#include <cstdint>
#include <string>
#include <vector>
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
         * 
         * IMPORTANT: Compile en HS_MODE_BLOCK (pas STREAM) pour performance maximale.
         */
        bool init(const std::string& patterns_path);

        /**
         * Scan un buffer en mode BLOCK.
         * C'est la méthode principale - utilisée pour TOUT le trafic.
         * Retourne true dès qu'un pattern matche (quelconque).
         * 
         * @param data Pointeur vers les données
         * @param len Taille des données
         * @return true si au moins un pattern a matché
         */
        bool scan(const uint8_t* data, size_t len) const;

        /**
         * Scan complet : Collecte TOUS les IDs qui matchent dans un vector.
         * Plus efficace que std::set car on évite l'overhead d'allocation.
         * 
         * @param data Pointeur vers les données
         * @param len Taille des données
         * @param[out] matched_ids Vector qui recevra les IDs matchés
         * @return true si au moins un pattern a matché
         */
        bool scan_collect_all(const uint8_t* data, size_t len,
                              std::vector<uint32_t>& matched_ids) const;

        /**
         * Retourne le nombre de patterns compilés.
         */
        uint32_t pattern_count() const { return pattern_count_; }

        /**
         * Vérifie si la DB est initialisée et prête.
         */
        bool is_ready() const { return db_ != nullptr && scratch_ != nullptr; }

    private:
        hs_database_t* db_ = nullptr;
        hs_scratch_t* scratch_ = nullptr;
        uint32_t pattern_count_ = 0;

        // Helper pour convertir "ims" -> HS_FLAG_CASELESS | HS_FLAG_MULTILINE | HS_FLAG_DOTALL
        static unsigned int parse_flags(const std::string& flags_str);
    };

}

#endif // FOX_DEEP_HS_MATCHER_HPP
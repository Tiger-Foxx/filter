#ifndef FOX_VERDICT_HPP
#define FOX_VERDICT_HPP

#include <cstdint>

namespace fox {

    /**
     * Decision finale rendue par le moteur pour un paquet donné.
     * Mappé directement sur les verdicts libnetfilter_queue.
     */
    enum class Verdict : uint8_t {
        ACCEPT = 0, //Paquet légitime, laisser passer
        DROP   = 1  //Paquet malveillant, destruction immédiate
    };

    /**
     * États internes du pipeline de décision.
     * Utilisé pour la communication entre les étages (FastPath -> DeepPath).
     */
    enum class PipelineStatus : uint8_t {
        PASS,           //Pas de match dans ce layer, continuer
        MATCH_DROP,     //Match règle bloquante
        MATCH_INSPECT   //Match règle nécessitant inspection (payload)
    };
}

#endif //FOX_VERDICT_HPP
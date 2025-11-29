#ifndef FOX_FASTPATH_PORT_MAP_HPP
#define FOX_FASTPATH_PORT_MAP_HPP

#include <cstdint>
#include <vector>
#include <array>
#include <bitset>
#include "../core/types.hpp"

namespace fox::fastpath {

    /**
     * Structure de Lookup Port ultra-rapide.
     * Permet de vérifier si un port appartient à une règle donnée en O(1) ?
     * * NOTE D'ARCHITECTURE:
     * Avec la fusion géométrique, une règle contient une LISTE de plages de ports.
     * Vérifier "Port in Rule.dst_ports" peut être O(N_ranges).
     * * Pour accélérer, on utilise souvent une Bitset de 65536 bits pour savoir
     * si un port est "intéressant" globalement, ou une table de lookup inverse.
     * * Ici, nous fournissons un helper optimisé pour valider un port contre une règle.
     */
    class PortMatcher {
    public:
        // Vérifie si un port (Host Order) est dans les plages de la règle
        // Complexité: O(Nombre de plages dans la règle). 
        // Comme l'optimiseur minimise les plages, c'est très rapide (souvent 1 ou 2 plages).
        static bool match(uint16_t port, const fox::core::RuleDefinition& rule) {
            for (const auto& range : rule.dst_ports) {
                if (port >= range.start && port <= range.end) {
                    return true;
                }
            }
            return false;
        }

        // Vérification Source Port (moins courant mais supporté)
        static bool match_src(uint16_t port, const fox::core::RuleDefinition& rule) {
            if (rule.src_ports.empty()) return true; // ANY par défaut si vide
            for (const auto& range : rule.src_ports) {
                if (port >= range.start && port <= range.end) {
                    return true;
                }
            }
            return false;
        }
    };
    
    // Pour l'instant, pas besoin de `port_table[65536]` complexe 
    // car le point d'entrée principal est le Trie IP.
    // L'implémentation "Tableau plat" de la SPECS.MD (3.2.B) servait surtout 
    // si on faisait le lookup Port AVANT l'IP, ou en parallèle.
    // Nous utiliserons ce PortMatcher une fois la règle IP trouvée.
}

#endif // FOX_FASTPATH_PORT_MAP_HPP
# FOX Engine - Optimisations TCP Haute Performance

## Vue d'ensemble des améliorations

Ce document décrit les optimisations implémentées pour atteindre des performances comparables à Snort/Suricata dans le réassemblage TCP et l'inspection de paquets.

---

## 1. Ring Buffer pré-alloué (TcpStreamFast)

### Problème initial
```cpp
// Ancien code: allocation dynamique à chaque segment
std::vector<uint8_t> _reassembled_buffer;  // O(n) réallocation
std::map<uint32_t, std::vector<uint8_t>> _ooo_segments;  // O(log n) lookup
```

### Solution
```cpp
// Nouveau: ring buffer fixe 64KB avec pointeurs head/tail
alignas(64) std::array<uint8_t, 65536> _ring_buffer;
size_t _ring_head = 0;  // Position de lecture
size_t _ring_tail = 0;  // Position d'écriture
```

### Bénéfices
- **Zéro allocation runtime** - tout est pré-alloué
- **Locality cache** - données contiguës alignées sur cache-line
- **O(1) insertion/lecture** vs O(n) pour std::vector

---

## 2. Table de Hash ouverte pour les flux (TcpReassemblerFast)

### Problème initial
```cpp
std::unordered_map<FlowKey, TcpStream> _flows;  // Allocations heap
```

### Solution
```cpp
// Pool pré-alloué + table de hash à probing linéaire
std::array<TcpStreamFast, 65536> _stream_pool;
std::array<FlowEntry, 131072> _hash_table;  // Load factor 0.5
std::array<uint32_t, 65536> _freelist;
```

### Bénéfices
- **Zéro new/delete** pendant le runtime
- **Cache-friendly** - accès séquentiel mémoire
- **Freelist O(1)** pour recyclage des streams

---

## 3. Segments OOO en tableau fixe

### Problème initial
```cpp
std::map<uint32_t, std::vector<uint8_t>> _ooo_segments;
// O(log n) insertion + allocation par segment
```

### Solution
```cpp
struct OOOSegment {
    uint32_t seq;
    uint16_t len;
    bool used;
    alignas(64) uint8_t data[1500];  // Inline MTU
};
std::array<OOOSegment, 32> _ooo_segments;
```

### Bénéfices
- **O(1) lookup** via scan linéaire (32 éléments max)
- **Données inline** - pas de pointeur vers heap
- **Prédictible** - comportement cache constant

---

## 4. Branch Prediction Hints

### Utilisation de `__builtin_expect`
```cpp
// Cas commun: pas de règle
if (__builtin_expect(rule == nullptr, 1)) {
    return Verdict::ACCEPT;
}

// Cas rare: ANY IP
if (__builtin_expect(cidrs.empty(), 0)) {
    return true;
}
```

### Bénéfices
- **Pipeline CPU** optimisé pour le cas courant
- Réduction des *branch mispredictions*

---

## 5. Attributs de fonction

```cpp
[[nodiscard]] __attribute__((hot)) 
Verdict process(const Packet& pkt) noexcept;

[[nodiscard]] __attribute__((noinline))
Verdict process_deep(const Packet& pkt, const RuleDefinition* rule) noexcept;
```

### Stratégie
- **`hot`** : Inline agressif du chemin principal (FastPath)
- **`noinline`** : Séparer DeepPath pour éviter code bloat

---

## 6. Alignement Cache-Line

```cpp
class alignas(64) TcpStreamFast {
    // Données chaudes groupées
    alignas(64) uint32_t _next_seq = 0;
    hs_stream_t* _hs_stream = nullptr;
    // ...
};
```

### Bénéfices
- **Évite false sharing** en multi-thread
- **Prefetch efficace** par le CPU

---

## 7. Scan Hyperscan incrémental

### Ancien modèle
```
Accumule tous les segments → Scan à la fin
```

### Nouveau modèle
```
Segment reçu → Écrit ring buffer → Scan immédiat → Mark scanned
```

### Bénéfices
- **Détection plus rapide** des patterns
- **Mémoire constante** (pas d'accumulation)
- **Latence réduite** pour le premier match

---

## 8. Compilation optimisée (CMake)

```cmake
# Flags performance
-O3 -march=native -mtune=native -flto
-funroll-loops -fomit-frame-pointer
-ffast-math
-falign-functions=64 -falign-loops=32
```

---

## Comparatif de complexité

| Opération           | Avant          | Après          |
|---------------------|----------------|----------------|
| Segment TCP insert  | O(n) + alloc   | O(1) amortized |
| Lookup flux         | O(1) expected  | O(1) amortized |
| OOO segment store   | O(log n) + alloc | O(1)         |
| Cleanup flux expirés| O(n)           | O(n) lazy     |

---

## Utilisation

### Activer le mode haute performance (défaut)
```bash
mkdir build && cd build
cmake .. -DUSE_FAST_ENGINE=ON
make -j$(nproc)
```

### Mode standard (debug/validation)
```bash
cmake .. -DUSE_FAST_ENGINE=OFF
```

---

## Statistiques runtime

Le moteur affiche les statistiques à l'arrêt :
```
Stats: 1234567 packets, 456 active TCP flows
```

Pour monitoring temps réel, utiliser `pcap` ou `conntrack`.

---

## Notes techniques

1. **Taille du pool** : 65536 flux simultanés max. Ajustable dans `config.hpp`.
2. **Ring buffer** : 64KB par flux. Suffisant pour ~45 paquets full-size.
3. **Timeout** : 60 secondes d'inactivité par défaut.
4. **Cleanup** : Tous les 65536 paquets (lazy garbage collection).

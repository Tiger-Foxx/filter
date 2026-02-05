# FOX Engine - Documentation de Recherche

## Unified Network Security Filter: Aggregating IPS, Firewall, and WAF Rules

**Date**: Février 2026  
**Version**: functionnal-multi-3-threads-6000-req  
**Auteurs**: Équipe de recherche Fox

---

## 1. Problème de Recherche

### 1.1 Contexte

Dans les architectures de sécurité réseau traditionnelles, le trafic traverse une **chaîne de filtrage** composée de plusieurs composants distincts :

```
┌─────────┐    ┌──────────┐    ┌─────┐    ┌─────────┐
│ Client  │───▶│ Firewall │───▶│ IPS │───▶│   WAF   │───▶ Serveur
└─────────┘    └──────────┘    └─────┘    └─────────┘
                    │              │           │
                    ▼              ▼           ▼
               Latence +      Latence +    Latence +
               Overhead       Overhead     Overhead
```

**Problèmes identifiés :**

1. **Latence cumulative** : Chaque composant ajoute sa propre latence de traitement
2. **Duplication des inspections** : Le même paquet est parsé plusieurs fois
3. **Overhead de communication** : Passage entre processus/conteneurs différents
4. **Scalabilité limitée** : Difficile de paralléliser une chaîne séquentielle
5. **Règles redondantes** : Les différents outils peuvent avoir des règles qui se chevauchent

### 1.2 Mesure du Problème

Sur notre banc de test CloudLab (8 cores), une chaîne traditionnelle composée de :
- **iptables** (Firewall L3/L4)
- **Suricata** (IPS)
- **ModSecurity** (WAF)

**Résultat** : ~2000 req/sec maximum, avec une latence élevée.

### 1.3 Question de Recherche

> *Est-il possible d'agréger les règles de Firewall, IPS et WAF en un seul moteur de filtrage unifié, tout en maintenant une performance significativement supérieure à la chaîne traditionnelle ?*

---

## 2. Contribution Principale

### 2.1 Solution Proposée : FOX Engine

FOX Engine est un **filtre de sécurité réseau unifié** qui :

1. **Agrège** les règles de multiples sources (Snort, Suricata, ModSecurity, iptables)
2. **Déduplique** et **optimise** les patterns au niveau sémantique
3. **Compile** tous les patterns en une seule base de données Hyperscan
4. **Filtre** en userspace avec NFQUEUE, multi-threadé

```
┌─────────┐    ┌───────────────────────────────────────┐
│ Client  │───▶│           FOX ENGINE                  │───▶ Serveur
└─────────┘    │  ┌─────────────────────────────────┐  │
               │  │ Unified Rule Database           │  │
               │  │ (Firewall + IPS + WAF patterns) │  │
               │  └─────────────────────────────────┘  │
               └───────────────────────────────────────┘
                              │
                              ▼
                    Une seule inspection
                    Multi-threadée
```

### 2.2 Résultats Obtenus

| Configuration | Requêtes/sec | Latence Moyenne | Threads Actifs |
|---------------|--------------|-----------------|----------------|
| Chaîne traditionnelle (FW+IPS+WAF) | ~2,000 | ~250ms | N/A |
| FOX Engine (1 thread) | ~2,500 | ~200ms | 1 |
| **FOX Engine (3 threads)** | **~6,400** | **~83ms** | **3** |

**Gain de performance** : **3.2x** par rapport à la chaîne traditionnelle.

### 2.3 Pourquoi FOX est Rapide

#### A. Hyperscan : Moteur de Pattern Matching Haute Performance

[Hyperscan](https://github.com/intel/hyperscan) est une bibliothèque Intel de pattern matching qui :

- **Compile** des milliers de regex en un seul automate DFA/NFA hybride
- Utilise les **instructions SIMD** (SSE4.2, AVX2, AVX-512) du CPU
- Permet de scanner **une seule fois** pour tous les patterns simultanément

```
Traditionnel (N patterns) :
  for each pattern:
    scan(data, pattern)  // O(N × |data|)

Hyperscan (N patterns compilés) :
  hs_scan(data, compiled_db)  // O(|data|) - indépendant de N !
```

**Impact** : 4370 patterns compilés, performance quasi-constante quelle que soit la quantité de règles.

#### B. Mode BLOCK vs Mode STREAM

Hyperscan propose deux modes :
- **STREAM** : Maintient un état par connexion TCP (lent, overhead mémoire)
- **BLOCK** : Scan direct sur un buffer complet (rapide, sans état)

**FOX utilise le mode BLOCK** comme Suricata. Le réassemblage TCP se fait **avant** le scan Hyperscan, pas pendant.

#### C. Architecture Zero-Copy

```cpp
// Pas de copie du paquet - on travaille directement sur le buffer kernel
std::span<uint8_t> packet_span(raw_data, len);
fox::core::Packet pkt(packet_span);  // Wrapper zero-copy
```

#### D. Index Composite O(1)

Au lieu de parcourir 3126 règles pour chaque paquet :

```
CompositeRuleIndex = IP Radix Trie + Port Hash Map

lookup(src_ip, dst_port) → Liste réduite de règles candidates
```

Seules les règles pertinentes sont vérifiées après le scan Hyperscan.

#### E. Sacrifice du Reporting pour la Vitesse

- **Pas de logging** par défaut (configurable)
- **Verdict binaire** : ACCEPT ou DROP
- **Pas de génération d'alertes** détaillées en temps réel

Ce trade-off est acceptable pour un use-case où la priorité est le filtrage, pas l'analyse forensique.

---

## 3. Architecture Détaillée

### 3.1 Vue d'Ensemble

```
                    ┌─────────────────────────────────────────────────┐
                    │                   FOX SYSTEM                     │
                    │                                                  │
┌──────────┐        │  ┌─────────────┐         ┌─────────────────┐    │
│  Rules   │        │  │  OPTIMIZER  │         │     FILTER      │    │
│  Sources │───────▶│  │  (Python)   │────────▶│     (C++17)     │    │
│          │        │  │             │         │                 │    │
│ - Snort  │        │  │ - Parse     │         │ - NFQUEUE       │    │
│ - Suricata│       │  │ - Clean     │         │ - Hyperscan     │    │
│ - ModSec │        │  │ - Dedupe    │         │ - Multi-Thread  │    │
│ - Custom │        │  │ - Export    │         │                 │    │
└──────────┘        │  └─────────────┘         └─────────────────┘    │
                    │        │                         ▲               │
                    │        ▼                         │               │
                    │  ┌─────────────┐                 │               │
                    │  │  Artifacts  │─────────────────┘               │
                    │  │             │                                 │
                    │  │ - patterns.txt (Hyperscan)                    │
                    │  │ - rules_config.msgpack (Logique)              │
                    │  │ - firewall.sh (iptables L3/L4)                │
                    │  └─────────────┘                                 │
                    └─────────────────────────────────────────────────┘
```

### 3.2 L'Optimizer (Python)

L'Optimizer transforme des règles hétérogènes en artefacts optimisés.

#### 3.2.1 Pipeline de Traitement

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Parser    │───▶│   Cleaner   │───▶│  Deduplicator│──▶│  Exporter   │
│             │    │             │    │             │    │             │
│ Snort/Suri  │    │ - Normalize │    │ - Exact     │    │ - patterns  │
│ format      │    │ - Fix regex │    │ - Semantic  │    │ - msgpack   │
│             │    │ - Validate  │    │   (future)  │    │ - firewall  │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

#### 3.2.2 Extraction Intelligente des Règles

Pour chaque règle Snort/Suricata, l'Optimizer extrait :

**1. Patterns de contenu** → `patterns.txt` (Hyperscan)
```
# Format: ID:/regex/flags
1001:/alert\s*\(/is
1002:/<script[^>]*>/is
```

**2. Métadonnées de règle** → `rules_config.msgpack`
```python
{
    "sid": 1001,
    "msg": "XSS Attack Detected",
    "src_ips": ["any"],
    "dst_ports": [80, 443],
    "hs_id": 1001,  # Référence au pattern Hyperscan
    "action": "drop"
}
```

**3. Règles L3/L4 pures** → `firewall.sh`
```bash
# Règles sans inspection de contenu = directement en iptables
iptables -A FORWARD -s 192.168.1.0/24 -d 10.0.0.0/8 -j DROP
```

#### 3.2.3 Déduplication des Patterns

```python
# Avant déduplication
Pattern 1: /[<>]script/i    (Rule A)
Pattern 2: /<script>/i      (Rule B)  
Pattern 3: /[<>]script/i    (Rule C)  # Doublon exact de Pattern 1

# Après déduplication
Pattern 1: /[<>]script/i    (Rules A, C)  # Fusionnées
Pattern 2: /<script>/i      (Rule B)
```

**Résultat** : De 5643 patterns bruts → 4370 patterns uniques compilés.

#### 3.2.4 Gestion des Règles Multi-Content

Certaines règles Snort ont plusieurs `content:` avec logique AND/OR :

```
alert tcp any any -> any 80 (content:"GET"; content:"/admin"; sid:1001;)
```

L'Optimizer crée :
- Pattern atomique 1001a : `GET`
- Pattern atomique 1001b : `/admin`
- Règle 1001 avec `atomic_ids: [1001a, 1001b]` et `is_or: false` (AND)

Le filtre vérifie ensuite la logique combinatoire après le scan Hyperscan.

### 3.3 Le Filtre (C++17)

#### 3.3.1 Architecture Multi-Thread

```
                     Kernel (iptables)
                           │
              iptables -j NFQUEUE --queue-balance 0:3 --queue-cpu-fanout
                           │
            ┌──────────────┼──────────────┬──────────────┐
            │              │              │              │
            ▼              ▼              ▼              ▼
       ┌────────┐    ┌────────┐    ┌────────┐    ┌────────┐
       │Queue 0 │    │Queue 1 │    │Queue 2 │    │Queue 3 │
       │Thread 0│    │Thread 1│    │Thread 2│    │Thread 3│
       │        │    │        │    │        │    │        │
       │scratch │    │scratch │    │scratch │    │scratch │
       │reassem │    │reassem │    │reassem │    │reassem │
       └────────┘    └────────┘    └────────┘    └────────┘
            │              │              │              │
            └──────────────┴──────────────┴──────────────┘
                                   │
                              Verdict:
                           NF_ACCEPT / NF_DROP
```

**Principe de distribution** :
- Le kernel calcule un hash sur le 5-tuple (src_ip, dst_ip, src_port, dst_port, proto)
- Avec `--queue-cpu-fanout`, le CPU qui reçoit le paquet détermine la queue
- **Garantie** : Tous les paquets d'un même flux TCP → même queue → même thread
- **Conséquence** : Pas de locks nécessaires sur les structures TCP

#### 3.3.2 Pipeline de Traitement d'un Paquet

```
Paquet entrant
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│ NIVEAU 0.5 : Fast-Path Mémoïsé                              │
│ ─────────────────────────────────────────                   │
│ Si le flux est déjà marqué MALICIOUS → DROP immédiat        │
│ (Évite de re-scanner les paquets suivants d'une attaque)    │
└─────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│ NIVEAU 1 : FastPath Index                                   │
│ ─────────────────────────────────────────                   │
│ CompositeRuleIndex.lookup(src_ip, dst_port)                 │
│ → Liste réduite de règles candidates                        │
│ Si vide → ACCEPT (pas de règle applicable)                  │
└─────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│ NIVEAU 2 : Réassemblage TCP (Mode Simplex)                  │
│ ─────────────────────────────────────────                   │
│ Pour TCP : Réassembler les segments dans l'ordre            │
│ Mode SIMPLEX : On scanne UNIQUEMENT Client→Serveur          │
│ (Le trafic Serveur→Client passe sans inspection deep)       │
└─────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│ NIVEAU 3 : Scan Hyperscan (Mode BLOCK)                      │
│ ─────────────────────────────────────────                   │
│ hs_scan(data, compiled_db, scratch)                         │
│ → Liste des pattern IDs qui ont matché                      │
└─────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│ NIVEAU 4 : Vérification des Règles                          │
│ ─────────────────────────────────────────                   │
│ Pour chaque règle candidate :                               │
│   - Vérifier IP destination                                 │
│   - Vérifier port source                                    │
│   - Vérifier protocole                                      │
│   - Vérifier logique multi-pattern (AND/OR)                 │
│ Si match → Appliquer verdict (DROP)                         │
└─────────────────────────────────────────────────────────────┘
      │
      ▼
   Verdict: ACCEPT ou DROP
```

#### 3.3.3 Hyperscan Thread-Safety

Hyperscan a une contrainte : le "scratch space" n'est **pas thread-safe**.

**Solution** : Chaque thread alloue son propre scratch :

```cpp
// Dans HSMatcher
hs_scratch_t* alloc_scratch_for_thread() const {
    hs_scratch_t* thread_scratch = nullptr;
    hs_alloc_scratch(db_, &thread_scratch);
    return thread_scratch;
}

// Dans NFQueueMulti::init()
ctx->scratch = matcher->alloc_scratch_for_thread();
ctx->reassembler = std::make_unique<TcpReassembler>(matcher, ctx->scratch);
```

---

## 4. Banc de Test

### 4.1 Topologie

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│    INJECTOR     │         │     FILTER      │         │     SERVER      │
│   10.10.1.10    │────────▶│   10.10.1.1     │────────▶│   10.10.2.20    │
│                 │  eno3   │   10.10.2.1     │ enp5s0f0│                 │
│   (wrk client)  │         │  (FOX Engine)   │         │   (nginx)       │
└─────────────────┘         └─────────────────┘         └─────────────────┘
     Client Net                                              Server Net
    10.10.1.0/24                                            10.10.2.0/24
```

### 4.2 Machines CloudLab

| Rôle | Hostname | CPU | RAM | OS |
|------|----------|-----|-----|-----|
| Injector | injector | 8 cores | 16GB | Ubuntu 22.04 |
| Filter | filter | 8 cores | 16GB | Ubuntu 22.04 |
| Server | server | 8 cores | 16GB | Ubuntu 22.04 |

### 4.3 Configuration du Serveur (nginx)

```bash
# Installation
sudo apt install nginx

# Config minimale pour benchmark
# /etc/nginx/nginx.conf
worker_processes auto;
events {
    worker_connections 4096;
}
```

### 4.4 Configuration de l'Injecteur (wrk)

```bash
# Installation
sudo apt install wrk

# Benchmark standard
sudo wrk -t 4 -c 500 -d 30 http://10.10.2.20/
```

---

## 5. Guide d'Installation et d'Utilisation

### 5.1 Prérequis (Machine Filter)

```bash
# Dépendances système
sudo apt update
sudo apt install build-essential cmake git
sudo apt install libhyperscan-dev libnetfilter-queue-dev libnfnetlink-dev
sudo apt install python3 python3-pip

# Dépendances Python (Optimizer)
cd optimizer
pip3 install -r requirements.txt
```

### 5.2 Compilation du Filtre

```bash
cd filter
./build.sh
```

Le script `build.sh` :
1. Crée le répertoire `build/`
2. Exécute `cmake ..`
3. Compile avec `make -j$(nproc)`

### 5.3 Génération des Artefacts (Optimizer)

```bash
cd optimizer

# Placer vos règles dans inputs/
cp /path/to/snort3-community.rules inputs/

# Lancer l'optimizer
python3 main.py

# Les artefacts sont générés dans outputs/
ls outputs/
# patterns.txt
# rules_config.msgpack
# firewall.sh
```

### 5.4 Copier les Artefacts vers le Filtre

```bash
cp optimizer/outputs/* filter/data/
```

### 5.5 Configuration NFQUEUE

```bash
cd filter

# Configurer iptables pour rediriger le trafic vers FOX
sudo ./setup_nfqueue.sh

# Vérifier la configuration
sudo ./setup_nfqueue.sh status

# Pour nettoyer
sudo ./setup_nfqueue.sh clean
```

### 5.6 Modifier les Interfaces Réseau

Si vos interfaces sont différentes, éditez `setup_nfqueue.sh` :

```bash
# Lignes à modifier (autour de la ligne 30)
CLIENT_IFACE="eno3"       # Interface côté client (à adapter)
SERVER_IFACE="enp5s0f0"   # Interface côté serveur (à adapter)

# Et les réseaux si nécessaire
CLIENT_NET="10.10.1.0/24"
SERVER_NET="10.10.2.0/24"
```

### 5.7 Lancer le Moteur

```bash
cd filter
sudo ./build/fox-engine
```

### 5.8 Application des Règles Firewall L3/L4

Les règles purement L3/L4 (sans inspection de contenu) sont exportées dans `firewall.sh`.

Pour les appliquer :
```bash
cd filter/data
chmod +x firewall.sh
sudo ./firewall.sh
```

**Note** : Pour l'instant, ces règles sont skippées par défaut en mode test.

---

## 6. Résultats Détaillés

### 6.1 Test Multi-Thread (3 threads actifs sur 4)

```
[INFO] === FOX ENGINE (Multi-Thread IPS) ===
[INFO] Threads: 4
[INFO] Hyperscan compiled 4370 patterns (BLOCK Mode - Multi-Thread Ready)
[INFO] Parsed 3126 optimized rules.

[STATS] 7122 pkt/s | Total: 37194 | Drop: 0 | T0:12501 T1:0 T2:12308 T3:12386
[STATS] 7263 pkt/s | Total: 73513 | Drop: 0 | T0:24777 T1:0 T2:24336 T3:24400
[STATS] 7273 pkt/s | Total: 109878 | Drop: 0 | T0:37030 T1:0 T2:36215 T3:36633

=== FINAL STATS ===
  Thread 0: 65791 packets, 0 dropped
  Thread 1: 0 packets, 0 dropped
  Thread 2: 63732 packets, 0 dropped
  Thread 3: 74422 packets, 0 dropped
  TOTAL: 203945 packets, 0 dropped
```

```
$ sudo wrk -t 4 -c 500 -d 30 http://10.10.2.20/
Running 30s test @ http://10.10.2.20/
  4 threads and 500 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    83.05ms   66.34ms 217.16ms   59.11%
    Req/Sec     1.62k   459.70     4.11k    77.50%
  193634 requests in 30.07s, 48.74MB read
Requests/sec:   6438.37
Transfer/sec:      1.62MB
```

### 6.2 Analyse de la Distribution

- **T1 = 0** : Le hash du 5-tuple depuis une seule IP source ne distribue pas sur cette queue
- **T0, T2, T3** : Répartition équilibrée grâce à `--queue-cpu-fanout` et RPS
- **En production** : Avec plusieurs IPs clients, les 4 threads seraient utilisés

### 6.3 Comparaison avec Baseline

| Métrique | Chaîne Traditionnelle | FOX (1 thread) | FOX (3 threads) |
|----------|----------------------|----------------|-----------------|
| Débit | ~2,000 req/s | ~2,500 req/s | **~6,400 req/s** |
| Latence | ~250ms | ~200ms | **~83ms** |
| Gain | baseline | 1.25x | **3.2x** |

---

## 7. Limites et Trade-offs

### 7.1 Ce que FOX Sacrifie

1. **Reporting détaillé** : Pas de génération d'alertes en temps réel
2. **Logging** : Désactivé par défaut pour la performance
3. **Flexibilité** : Les règles doivent être recompilées pour modification
4. **Inspection bidirectionnelle** : Mode Simplex (Client→Serveur uniquement)

### 7.2 Quand FOX est le Plus Performant

- ✅ Agrégation de **multiples bases de règles** (IPS + WAF + Custom)
- ✅ Scénarios à **haut débit** où la chaîne traditionnelle est un bottleneck
- ✅ Environnements où le **filtrage** prime sur l'**analyse**
- ✅ Trafic provenant de **multiples sources** (distribution multi-thread)

### 7.3 Quand Éviter FOX

- ❌ Besoin de **forensics** et alertes détaillées
- ❌ Règles qui changent **fréquemment** (recompilation Hyperscan coûteuse)
- ❌ Inspection **bidirectionnelle** requise

---

## 8. Pistes d'Amélioration

### 8.1 Court Terme

1. **Batch Processing** : Traiter plusieurs paquets en un seul appel système
2. **Optimisation du Lookup** : Bloom filter avant l'index composite
3. **Profiling** : Identifier les hotspots avec `perf`

### 8.2 Moyen Terme

1. **Fusion Sémantique de Règles** : Regrouper les règles avec patterns similaires
   - Note : L'impact sur la vitesse serait limité car Hyperscan compile déjà tout en une seule DB optimisée
   - Intérêt : Réduire la vérification logique post-scan

2. **Mode Kernel (XDP/eBPF)** : Filtrage encore plus proche du hardware
3. **Support des Règles Dynamiques** : Rechargement à chaud sans recompilation

### 8.3 Long Terme

1. **Apprentissage** : Détection d'anomalies basée sur le trafic normal
2. **Distributed FOX** : Plusieurs instances avec load balancing
3. **Hardware Offload** : Utilisation de SmartNICs avec Hyperscan embarqué

---

## 9. Conclusion

FOX Engine démontre qu'il est possible de :

1. **Agréger** des règles de sources hétérogènes (Firewall, IPS, WAF)
2. **Compiler** ces règles en une base de données Hyperscan unique
3. **Filtrer** avec une performance **3.2x supérieure** à la chaîne traditionnelle
4. **Paralléliser** le traitement sur plusieurs threads sans locks

La clé de cette performance réside dans :
- L'utilisation de **Hyperscan** pour le pattern matching O(n) indépendant du nombre de règles
- L'**architecture multi-thread** sans contention grâce à l'affinité de flux
- L'**index composite** pour réduire l'espace de recherche des règles
- Le **mode BLOCK** et l'architecture **zero-copy**

Ce travail ouvre la voie à des filtres de sécurité réseau **unifiés** et **haute performance**, particulièrement pertinents dans les contextes où la multiplication des outils de sécurité crée un bottleneck inacceptable.

---

## Annexes

### A. Structure des Fichiers

```
filter/
├── build.sh                 # Script de compilation
├── setup_nfqueue.sh         # Configuration iptables
├── CMakeLists.txt
├── data/                    # Artefacts générés par l'Optimizer
│   ├── patterns.txt         # Patterns Hyperscan
│   ├── rules_config.msgpack # Logique des règles
│   └── firewall.sh          # Règles iptables L3/L4
├── include/
│   ├── config.hpp           # Configuration (threads, timeouts, etc.)
│   ├── core/                # Structures de base (Packet, FlowKey, etc.)
│   ├── deep/                # Hyperscan + TCP Reassembly
│   ├── fastpath/            # Index composite (Radix + Port)
│   ├── io/                  # NFQUEUE + Loader
│   └── utils/               # Logger, Memory Pool
└── src/
    ├── main.cpp             # Point d'entrée
    ├── deep/                # Implémentation Hyperscan
    └── io/                  # Implémentation NFQUEUE

optimizer/
├── main.py                  # Point d'entrée
├── requirements.txt
├── inputs/                  # Règles sources
│   └── snort3-community.rules
├── outputs/                 # Artefacts générés
└── src/
    ├── parser.py            # Parsing Snort/Suricata
    ├── cleaner.py           # Normalisation des patterns
    ├── content_engine.py    # Extraction des contents
    ├── exporter.py          # Export patterns.txt + msgpack
    └── models.py            # Structures de données
```

### B. Format des Artefacts

#### patterns.txt
```
# ID:/regex/flags
# flags: i=caseless, m=multiline, s=dotall, H=singlematch
1001:/<script[^>]*>/is
1002:/javascript:/i
1003:/onerror\s*=/is
```

#### rules_config.msgpack
```python
{
    "rules": [
        {
            "sid": 1001,
            "msg": "XSS Detected",
            "src_ips": [...],
            "dst_ips": [...],
            "src_ports": [...],
            "dst_ports": [80, 443],
            "proto": "tcp",
            "hs_id": 1001,
            "atomic_ids": [],
            "is_multi": false,
            "is_or": false,
            "action": "drop"
        },
        ...
    ]
}
```

### C. Commandes Utiles

```bash
# Vérifier les règles iptables
sudo iptables -L FORWARD -v -n

# Voir les stats NFQUEUE en temps réel
watch -n 1 'cat /proc/net/netfilter/nfnetlink_queue'

# Profiler le moteur
sudo perf record -g ./build/fox-engine
sudo perf report

# Test de charge avec XSS
curl "http://10.10.2.20/?q=<script>alert(1)</script>"
```

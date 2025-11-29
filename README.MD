# FoxEngine (C++ Runtime)

**Type :** Moteur de Filtrage Réseau Haute Performance (Research PoC)  
**Langage :** C++20 (Strict Zero-Copy)  
**Architecture :** Hybride L3/L4 (Radix Trie) + L7 (Hyperscan Streaming)  
**Statut :** 🟢 Prêt pour Benchmark

---

## 1. Description Scientifique

Le **FoxEngine** est l'implémentation "Runtime" du projet de recherche sur l'optimisation des règles de filtrage. Contrairement aux IDS classiques (Snort, Suricata) qui réévaluent les règles séquentiellement ou par groupes génériques, FoxEngine est un exécutant "muet" conçu pour interpréter les structures mathématiques pré-calculées par l'optimiseur Python (`tiger-foxx-ids-rules-optimizer`).

### Objectifs de Performance
* **Complexité Algorithmique :** $O(1)$ ou $O(\log N)$ pour la décision de filtrage, quel que soit le nombre de règles.
* **Zero-Copy Networking :** Analyse des paquets directement dans le buffer mémoire du Kernel (via `libnetfilter_queue` mode `COPY_PACKET` mappé), sans allocation `std::string` ni copie intermédiaire.
* **Instruction Pipeline :** Utilisation intensive des instructions vectorielles (AVX2/AVX512) via Hyperscan pour le pattern matching.

---

## 2. Architecture Technique

Le moteur fonctionne selon un pipeline strict à 3 étages pour minimiser le coût CPU par paquet.

### Niveau 0 : Kernel Offload (Bash/Iptables)
* **Mécanisme :** Script `firewall.sh` généré.
* **Rôle :** Élimination immédiate des IP/Ports "bruit de fond" directement dans le noyau Linux. Les paquets ne montent jamais en Userspace.

### Niveau 1 : FastPath (C++ L3/L4)
* **Structure :** Radix Trie (Arbre préfixe) optimisé en mémoire.
* **Fonctionnement :**
    1.  Lookup IP Source/Destination ($O(32)$ constant).
    2.  Vérification Bitmap/Intervalle des Ports ($O(1)$).
    3.  **Décision :** Si aucune inspection profonde n'est requise (`hs_id == 0`), le verdict (ACCEPT/DROP) est rendu immédiatement (Latence < 5µs).

### Niveau 2 : DeepPath (C++ L7 Stateful)
* **Structure :** Réassemblage TCP + Intel Hyperscan.
* **Fonctionnement :**
    1.  Suivi de connexion (5-tuple Flow Tracking).
    2.  Réordonnancement des segments TCP (gestion des paquets *Out-of-Order*).
    3.  Scan de contenu via automates finis déterministes (DFA) streamés.

---

## 3. Pré-requis

Le moteur est conçu pour **Linux (x86_64)**.

### Dépendances Système
```bash
# Debian/Ubuntu
sudo apt update
sudo apt install -y \
    build-essential cmake \
    libnetfilter-queue-dev \
    libnfnetlink-dev \
    libmnl-dev \
    libhyperscan-dev \
    libmsgpack-dev \
    pkg-config
````

### Artefacts (Données)

Le moteur ne démarre pas "à vide". Il a impérativement besoin des fichiers générés par l'optimiseur Python, qui doivent être placés dans le dossier `data/` à la racine de l'exécutable :

1.  `data/firewall.sh`
2.  `data/patterns.txt`
3.  `data/rules_config.msgpack`

-----

## 4\. Compilation

Le projet utilise CMake. La compilation est configurée pour optimiser agressivement (`-O3 -march=native`).

```bash
mkdir build
cd build
cmake ..
make -j$(nproc)
```

L'exécutable binaire `fox-engine` sera généré dans `build/` (ou `bin/` selon configuration).

-----

## 5\. Usage

### Démarrage

Le moteur doit être exécuté avec les privilèges **root** pour pouvoir s'accrocher aux queues Netfilter du noyau.

```bash
# Depuis la racine du projet (pour trouver le dossier data/)
sudo ./build/fox-engine
```

Si tout fonctionne, vous verrez :

```text
[INFO] Loading Hyperscan patterns...
[INFO] Parsed X optimized rules.
[INFO] Initializing NFQUEUE interface on Queue ID 0...
[INFO] >>> Engine Running. Waiting for packets...
```

### Interception du Trafic

Par défaut, le moteur écoute sur la **Queue ID 0**. Vous devez rediriger le trafic que vous souhaitez inspecter vers cette queue via `iptables`.

**Exemple : Inspecter tout le trafic entrant (Attention : risque de coupure SSH si bug)**

```bash
sudo iptables -I INPUT -j NFQUEUE --queue-num 0
```

**Exemple sécurisé (Test local)**

```bash
# Inspecter seulement le trafic ICMP (Ping)
sudo iptables -I INPUT -p icmp -j NFQUEUE --queue-num 0
```

-----

## 6\. Structure du Code

```text
src/
├── main.cpp                  # Point d'entrée & Boucle principale
├── core/
│   ├── engine.hpp            # Orchestrateur (Singleton)
│   ├── packet.hpp            # Parsing Zero-Copy (IP/TCP/UDP headers)
│   └── types.hpp             # Structures de données (DTOs MessagePack)
├── fastpath/
│   ├── ip_radix.hpp          # Implémentation Radix Trie
│   └── port_map.hpp          # Logique de matching de ports
├── deep/
│   ├── hs_matcher.hpp        # Wrapper Intel Hyperscan
│   ├── tcp_stream.hpp        # Logique de flux (Sequencing/Reassembly)
│   └── tcp_reassembler.hpp   # Gestionnaire de sessions TCP
└── io/
    ├── loader.hpp            # Chargement msgpack & patterns
    └── nfqueue.hpp           # Interface Linux Netfilter
```

-----

## 7\. Limitations (PoC Scope)

  * **IPv4 Only :** Le Radix Trie actuel ne gère pas l'IPv6.
  * **Mono-thread :** Le moteur traite les paquets séquentiellement (suffisant pour la démonstration de latence unitaire, mais limitant pour le débit \> 10 Gbps).
  * **TCP Window :** La fenêtre de réassemblage est fixe (limite mémoire hardcodée pour éviter les DoS).

-----

**Auteur :** FoxEngine Team (Research Lab)  
**Licence :** MIT / Academic Research Use Only
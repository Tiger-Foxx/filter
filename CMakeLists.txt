cmake_minimum_required(VERSION 3.20)
project(fox-engine LANGUAGES CXX C)

# --- CONFIGURATION SCIENTIFIQUE & PERFORMANCE ---
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Flags d'optimisation :
# -O3 : Optimisation maximale du compilateur
# -march=native : Utilise les instructions spécifiques du CPU hôte (AVX2/AVX512)
# -mtune=native : Tweak le code pour le pipeline du CPU hôte
# -DNDEBUG : Désactive les assertions (assert) pour la prod
# -flto : Link Time Optimization (Optimisation globale inter-modules)
# -fno-rtti : Désactive l'introspection runtime (gain vtable)
if(NOT CMAKE_BUILD_TYPE MATCHES "Debug")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -march=native -mtune=native -DNDEBUG -flto -fno-rtti -Wall")
endif()

# --- DEPENDANCES ---
find_package(PkgConfig REQUIRED)

# 1. Netfilter (Interception Noyau)
pkg_check_modules(NFQ REQUIRED libnetfilter_queue)
pkg_check_modules(MNL REQUIRED libmnl) # Low-level Netlink communication

# 2. Hyperscan (Pattern Matching Vectorisé)
pkg_check_modules(HS REQUIRED libhs)

# 3. MessagePack (Désérialisation Binaire Zero-Copy)
# Note: msgpack est souvent header-only, mais on vérifie sa présence
find_path(MSGPACK_INCLUDE_DIR msgpack.hpp)
if(NOT MSGPACK_INCLUDE_DIR)
    message(FATAL_ERROR "msgpack-cxx headers not found")
endif()

# --- STRUCTURE ---
include_directories(
    include
    ${NFQ_INCLUDE_DIRS}
    ${MNL_INCLUDE_DIRS}
    ${HS_INCLUDE_DIRS}
    ${MSGPACK_INCLUDE_DIR}
)

# Inclusion automatique des sources (pour simplifier l'ajout futur)
file(GLOB_RECURSE SOURCES "src/*.cpp")

# --- TARGET ---
add_executable(fox-engine ${SOURCES})

target_link_libraries(fox-engine PRIVATE
    ${NFQ_LIBRARIES}
    ${MNL_LIBRARIES}
    ${HS_LIBRARIES}
    pthread
)

# --- INSTALLATION ---
install(TARGETS fox-engine DESTINATION bin)
cmake_minimum_required(VERSION 3.20)
project(fox-engine LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# === MODE HIGH PERFORMANCE (TCP Reassembly Optimisé) ===
option(USE_FAST_ENGINE "Use high-performance TCP reassembly engine" ON)
if(USE_FAST_ENGINE)
    add_compile_definitions(USE_FAST_ENGINE=1)
    message(STATUS ">>> High Performance Mode ENABLED")
else()
    add_compile_definitions(USE_FAST_ENGINE=0)
    message(STATUS ">>> Standard Mode (USE_FAST_ENGINE=OFF)")
endif()

# === Flags d'Optimisation Avancés ===
if(NOT CMAKE_BUILD_TYPE MATCHES "Debug")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -march=native -mtune=native -DNDEBUG -flto -fno-rtti -Wall")
    # Flags supplémentaires pour le mode haute performance
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -funroll-loops -fomit-frame-pointer")
    # Hints pour le compilateur sur le hot path
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ffast-math")
    # Cache locality optimization
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -falign-functions=64 -falign-loops=32")
endif()

# Flags de debug avec symbols
if(CMAKE_BUILD_TYPE MATCHES "Debug")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0 -Wall -Wextra")
endif()

# Dependencies
find_package(PkgConfig REQUIRED)

pkg_check_modules(NFQ REQUIRED libnetfilter_queue)
pkg_check_modules(NFNL REQUIRED libnfnetlink) # AJOUT CRITIQUE
pkg_check_modules(MNL REQUIRED libmnl)
pkg_check_modules(HS REQUIRED libhs)

# MessagePack (Header Only or Lib)
find_path(MSGPACK_INCLUDE_DIR msgpack.hpp)
if(NOT MSGPACK_INCLUDE_DIR)
    message(FATAL_ERROR "msgpack-cxx headers not found")
endif()

include_directories(
    include
    ${NFQ_INCLUDE_DIRS}
    ${NFNL_INCLUDE_DIRS}
    ${MNL_INCLUDE_DIRS}
    ${HS_INCLUDE_DIRS}
    ${MSGPACK_INCLUDE_DIR}
)

file(GLOB_RECURSE SOURCES "src/*.cpp")

add_executable(fox-engine ${SOURCES})

target_link_libraries(fox-engine PRIVATE
    ${NFQ_LIBRARIES}
    ${NFNL_LIBRARIES}
    ${MNL_LIBRARIES}
    ${HS_LIBRARIES}
    pthread
)

install(TARGETS fox-engine DESTINATION bin)
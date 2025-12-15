#ifndef FOX_UTILS_MEMORY_POOL_HPP
#define FOX_UTILS_MEMORY_POOL_HPP

/**
 * Memory Pool inspiré de Suricata (util-pool.h)
 * 
 * Objectif : Allocation O(1) sans appel système pendant le traitement des paquets.
 * 
 * Stratégie :
 * - Pré-allouer N blocs de taille fixe au démarrage
 * - Get() : Pop du stack libre en O(1)
 * - Return() : Push sur le stack libre en O(1)
 * - ZERO malloc/free pendant le runtime
 * 
 * Usage typique :
 *   MemoryPool<TcpStream, 100000> stream_pool;
 *   stream_pool.init();
 *   TcpStream* s = stream_pool.get();
 *   // ... utilisation ...
 *   stream_pool.release(s);
 */

#include <vector>
#include <cstdint>
#include <mutex>
#include <atomic>

namespace fox::utils {

    template<typename T, size_t MAX_ITEMS>
    class MemoryPool {
    public:
        MemoryPool() = default;
        
        ~MemoryPool() {
            // Libérer la mémoire pré-allouée
            if (_storage) {
                delete[] _storage;
            }
        }

        // Interdiction de copie
        MemoryPool(const MemoryPool&) = delete;
        MemoryPool& operator=(const MemoryPool&) = delete;

        /**
         * Initialise le pool avec MAX_ITEMS éléments pré-alloués.
         * Doit être appelé une seule fois au démarrage.
         */
        bool init() {
            if (_initialized) return true;

            try {
                // Allocation unique massive (évite la fragmentation)
                _storage = new T[MAX_ITEMS];
                
                // Initialiser le stack libre
                _free_stack.reserve(MAX_ITEMS);
                for (size_t i = 0; i < MAX_ITEMS; ++i) {
                    _free_stack.push_back(&_storage[i]);
                }
                
                _initialized = true;
                _allocated = MAX_ITEMS;
                _outstanding = 0;
                
                return true;
            } catch (...) {
                return false;
            }
        }

        /**
         * Obtient un élément du pool en O(1).
         * Retourne nullptr si le pool est épuisé.
         */
        T* get() {
            if (!_initialized || _free_stack.empty()) {
                return nullptr;
            }
            
            T* item = _free_stack.back();
            _free_stack.pop_back();
            _outstanding++;
            
            return item;
        }

        /**
         * Remet un élément dans le pool en O(1).
         * L'élément doit provenir de ce pool.
         */
        void release(T* item) {
            if (!item || !_initialized) return;
            
            // Vérification de bounds (debug)
            #ifndef NDEBUG
            if (item < _storage || item >= _storage + MAX_ITEMS) {
                return; // Item ne provient pas de ce pool
            }
            #endif
            
            _free_stack.push_back(item);
            _outstanding--;
        }

        // Stats
        size_t capacity() const { return MAX_ITEMS; }
        size_t available() const { return _free_stack.size(); }
        size_t outstanding() const { return _outstanding; }
        bool is_initialized() const { return _initialized; }

    private:
        T* _storage = nullptr;
        std::vector<T*> _free_stack;
        bool _initialized = false;
        size_t _allocated = 0;
        size_t _outstanding = 0;
    };

    /**
     * Version thread-safe du Memory Pool (pour multi-threading futur)
     */
    template<typename T, size_t MAX_ITEMS>
    class ThreadSafeMemoryPool {
    public:
        bool init() {
            std::lock_guard<std::mutex> lock(_mutex);
            return _pool.init();
        }

        T* get() {
            std::lock_guard<std::mutex> lock(_mutex);
            return _pool.get();
        }

        void release(T* item) {
            std::lock_guard<std::mutex> lock(_mutex);
            _pool.release(item);
        }

        size_t capacity() const { return _pool.capacity(); }
        size_t available() const { return _pool.available(); }
        size_t outstanding() const { return _pool.outstanding(); }

    private:
        MemoryPool<T, MAX_ITEMS> _pool;
        std::mutex _mutex;
    };

}

#endif // FOX_UTILS_MEMORY_POOL_HPP

#pragma once
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

struct NativeLibrary {
    std::string path;
    uintptr_t base = 0;
    std::vector<std::pair<uintptr_t, uintptr_t>> executable;
    uint64_t generation = 0;
    uint64_t retirement_order = 0;
    std::string key() const { return path + "\n" + std::to_string(base); }
    bool contains(uintptr_t address) const {
        for (const auto& range : executable) if (address >= range.first && address < range.second) return true;
        return false;
    }
};

// Serialized under the loader lock by the runtime. A real fini observation
// removes the generation immediately, so same-path/same-address reloads receive
// a fresh identity even when they occur between two periodic snapshots.
class NativeLibraries {
    std::map<std::string, NativeLibrary> loaded_;
    std::map<std::string, NativeLibrary> retiring_;
    uint64_t next_ = 0;
public:
    template<class Removed, class Added>
    void sync(std::vector<NativeLibrary> observed, Removed removed, Added added) {
        std::map<std::string, NativeLibrary> next;
        std::set<std::string> seen;
        for (auto& module : observed) {
            seen.insert(module.key());
            if (retiring_.count(module.key())) continue; // fini has run, but unmap may not have happened yet
            const auto old = loaded_.find(module.key());
            module.generation = old == loaded_.end() ? ++next_ : old->second.generation;
            next.emplace(module.key(), std::move(module));
        }
        for (const auto& item : loaded_) if (!next.count(item.first)) removed(item.second);
        for (const auto& item : next) if (!loaded_.count(item.first)) added(item.second);
        for (auto it = retiring_.begin(); it != retiring_.end();) {
            if (!seen.count(it->first)) { removed(it->second); it = retiring_.erase(it); }
            else ++it;
        }
        loaded_ = std::move(next);
    }
    template<class Removed> void fini(const std::string& path, uintptr_t base, Removed removed, uint64_t order = 0) {
        const auto key = path + "\n" + std::to_string(base);
        auto found = loaded_.find(key);
        if (found != loaded_.end()) {
            auto module = found->second; module.retirement_order = order;
            loaded_.erase(found); retiring_[key] = module; removed(module);
        }
    }
    template<class Removed> void arrived(const std::string& path, uintptr_t base, Removed removed) {
        const auto found = retiring_.find(path + "\n" + std::to_string(base));
        if (found != retiring_.end()) { removed(found->second); retiring_.erase(found); }
    }
    const std::map<std::string, NativeLibrary>& loaded() const { return loaded_; }
};

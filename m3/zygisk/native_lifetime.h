#pragma once
#include <cstddef>
#include <mutex>
#include <utility>

// The mutex protects choosing an original trampoline and incrementing its users
// as one operation. It is NEVER held while executing app code or waiting for it.
// A removal worker retries rather than blocking a thread that may need linker.
class NativeLifetime {
    mutable std::mutex mutex_;
    size_t users_ = 0;
    bool removed_ = false;
public:
    template<class Install> bool initialize(Install operation) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (users_) return false;
        if (!operation()) return false;
        removed_ = false;
        return true;
    }
    class Lease {
        NativeLifetime* owner_;
    public:
        const bool removed;
        Lease(NativeLifetime& owner, bool state) : owner_(&owner), removed(state) {}
        Lease(const Lease&) = delete;
        Lease(Lease&& other) noexcept : owner_(std::exchange(other.owner_, nullptr)), removed(other.removed) {}
        ~Lease() { if (owner_) { std::lock_guard<std::mutex> lock(owner_->mutex_); --owner_->users_; } }
    };
    Lease enter() {
        std::lock_guard<std::mutex> lock(mutex_);
        ++users_;
        return Lease(*this, removed_);
    }
    // 1 removed, 0 in flight (retry), -1 engine refused. Failed removal must not
    // release the registry slot or discard the original engine handle.
    template<class Remove> int remove(Remove operation) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (removed_) return 1;
        if (users_) return 0;
        if (!operation()) return -1;
        removed_ = true;
        return 1;
    }
    size_t users() const { std::lock_guard<std::mutex> lock(mutex_); return users_; }
    bool removed() const { std::lock_guard<std::mutex> lock(mutex_); return removed_; }
};

#pragma once
#include "third_party/json.hpp"
#include <mutex>
#include <string>

// Installation results, not a claim that libraries remain loaded forever.
// Async callbacks may run before the initial hook API returns. Terminal results
// must therefore never be overwritten by the API's provisional pending result.
class NativeHookStatus {
    using json = nlohmann::json;
    mutable std::mutex mutex_;
    json hooks_ = json::array();
    json engine_ = {{"status", "loading"}};
    json config_ = {{"status", "loading"}};
    json jni_ = json::array();
    uint64_t revision_ = 0;
    static bool terminal(const std::string& state) {
        return state == "installed" || state == "failed" || state == "timeout" || state == "rejected";
    }
public:
    size_t add(json metadata) {
        std::lock_guard<std::mutex> lock(mutex_);
        metadata["status"] = "pending";
        hooks_.push_back(std::move(metadata));
        ++revision_;
        return hooks_.size() - 1;
    }
    bool pending(size_t key) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return hooks_.at(key).at("status") == "pending";
    }
    bool claim(size_t key) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto& row = hooks_.at(key);
        if (row["status"] != "pending") return false;
        row["status"] = "installing";
        ++revision_;
        return true;
    }
    bool update(size_t key, const std::string& state, json detail = json::object()) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto& row = hooks_.at(key);
        if (terminal(row["status"].get<std::string>())) return false;
        row["status"] = state;
        row["detail"] = std::move(detail);
        ++revision_;
        return true;
    }
    bool symbol_result(size_t key, bool has_stub, int code, int pending_code,
                       bool completion_callback, const std::string& message) {
        if (code == pending_code)
            return update(key, "pending", {{"code", code}, {"reason", "library_not_loaded"},
                                          {"completion_callback", completion_callback}});
        return update(key, has_stub && code == 0 ? "installed" : "failed",
                      {{"code", code}, {"message", message}});
    }
    void engine(json value) {
        std::lock_guard<std::mutex> lock(mutex_);
        engine_ = std::move(value); ++revision_;
    }
    void configuration(json value) {
        std::lock_guard<std::mutex> lock(mutex_);
        config_ = std::move(value); ++revision_;
    }
    void jni(json value) {
        std::lock_guard<std::mutex> lock(mutex_);
        jni_ = std::move(value); ++revision_;
    }
    json snapshot() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return {{"kind", "native"}, {"native_status_version", 1}, {"revision", revision_},
                {"engine", engine_}, {"configuration", config_}, {"hooks", hooks_},
                {"jni_observers", jni_}, {"live_unhook", false}, {"live_reconcile", false},
                {"installation_scope", "process_start"}, {"unload_tracking", false}};
    }
};

#pragma once
#include "third_party/json.hpp"
#include <deque>
#include <mutex>
#include <string>
#include <vector>

namespace reconbridge {
// Bounded observations, not an authoritative VM binding table. Class names alone
// are never identities: two loaders can define the same binary name.
class JniBindings {
    using json = nlohmann::json;
    std::mutex mutex_;
    std::deque<json> rows_;
    size_t capacity_;
    uint64_t seq_ = 0, evicted_ = 0;
    static bool address(const json& value, uint64_t& out) {
        if (!value.is_string()) return false;
        const auto text = value.get<std::string>();
        if (text.size() < 3 || text.size() > 18 || text.substr(0, 2) != "0x") return false;
        out = 0;
        for (size_t i = 2; i < text.size(); ++i) {
            const char c = text[i];
            const int digit = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 :
                c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
            if (digit < 0) return false;
            out = out * 16 + digit;
        }
        return true;
    }
public:
    explicit JniBindings(size_t capacity = 4096) : capacity_(capacity ? capacity : 1) {}
    void ingest(json event, uint64_t connection) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!event.is_object()) return;
        for (const char* field : {"type", "package", "process_instance", "class_id", "class", "method", "signature", "address", "module"})
            if (event.contains(field) && !event[field].is_string()) return;
        const auto type = event.value("type", "");
        if (type == "native_library_unloading" || type == "native_library_unloaded") {
            if (!event.contains("executable_ranges") || !event["executable_ranges"].is_array() ||
                event["executable_ranges"].size() > 64 || !event.contains("observation_order") ||
                !event["observation_order"].is_number_unsigned()) return;
            std::vector<std::pair<uint64_t, uint64_t>> ranges;
            for (const auto& range : event["executable_ranges"]) {
                uint64_t start, end;
                if (!range.is_array() || range.size() != 2 || !address(range[0], start) || !address(range[1], end) || end <= start) return;
                ranges.push_back({start, end});
            }
            ++seq_;
            for (auto& row : rows_) {
                if (row["connection_id"] != connection || !row.contains("observation_order") ||
                    !row["observation_order"].is_number_unsigned() || row["observation_order"] >= event["observation_order"]) continue;
                const auto state = row.value("binding_status", "");
                if (state != "observed_registered" && state != "identity_unknown" && state != "module_unloading") continue;
                const auto module = row.value("module", "");
                if (!module.empty() && module != event.value("module", "")) continue;
                uint64_t ptr;
                if (!row.contains("address") || !address(row["address"], ptr)) continue;
                for (const auto& range : ranges) if (ptr >= range.first && ptr < range.second) {
                    row["binding_status"] = type == "native_library_unloading" ? "module_unloading" : "module_unloaded";
                    row["state_changed_seq"] = seq_;
                    row["unload_observation"] = {{"source", event.value("source", "")},
                        {"observation_order", event["observation_order"]}, {"module", event.value("module", "")}};
                    break;
                }
            }
            return;
        }
        if (type != "jni_registration" && type != "jni_unregistration" && type != "jni_class_collected") return;
        event["mapping_seq"] = ++seq_;
        event["connection_id"] = connection;
        const auto identity = event.value("class_id", "");
        const auto instance = event.value("process_instance", "");
        const bool known = !identity.empty() && !instance.empty();
        if (known) for (auto& row : rows_) {
            if (row["connection_id"] != connection || row.value("class_id", "") != identity ||
                row.value("process_instance", "") != instance || row["binding_status"] != "observed_registered") continue;
            if (type == "jni_registration" && (row.value("method", "") != event.value("method", "") ||
                row.value("signature", "") != event.value("signature", ""))) continue;
            row["binding_status"] = type == "jni_registration" ? "superseded" :
                type == "jni_unregistration" ? "unregistered" : "class_collected";
            row["state_changed_seq"] = seq_;
        }
        if (type != "jni_registration") return;
        event["binding_status"] = known ? "observed_registered" : "identity_unknown";
        event["runtime_connected"] = true;
        event["current_binding_verified"] = false;
        rows_.push_back(std::move(event));
        if (rows_.size() > capacity_) { rows_.pop_front(); ++evicted_; }
    }
    void disconnect(uint64_t connection) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& row : rows_) if (row["connection_id"] == connection) {
            row["runtime_connected"] = false;
            if (row["binding_status"] == "observed_registered" || row["binding_status"] == "identity_unknown")
                row["binding_status"] = "runtime_disconnected";
        }
    }
    json snapshot(const std::string& package, const std::string& filter, size_t limit, bool include_inactive) {
        std::lock_guard<std::mutex> lock(mutex_);
        json bindings = json::array();
        for (const auto& row : rows_) {
            if (row.value("package", "") != package || row.value("class", "").find(filter) == std::string::npos) continue;
            if (!include_inactive && row["binding_status"] != "observed_registered") continue;
            bindings.push_back(row);
        }
        const size_t available = bindings.size();
        if (available > limit) bindings.erase(bindings.begin(), bindings.begin() + (available - limit));
        return {{"package", package}, {"mapping_version", 3}, {"count", bindings.size()},
            {"bindings", bindings}, {"available", available}, {"result_truncated", available > limit},
            {"mapping_cache", {{"capacity", capacity_}, {"retained", rows_.size()}, {"evicted_total", evicted_}, {"latest_seq", seq_}}},
            {"current_bindings_verified", false},
            {"coverage", "observed registration lifecycle; excludes earlier registrations and static resolution; concurrent VM operations and upstream loss may leave state uncertain"}};
    }
};
} // namespace reconbridge

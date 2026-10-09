// Host-testable, bounded event transport. Completeness starts at daemon ingress.
#pragma once
#include "third_party/json.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <random>
#include <set>
#include <string>

namespace reconbridge {
using json = nlohmann::json;
struct Subscriber {
    std::mutex m;
    std::condition_variable cv;
    std::deque<std::string> q;
    bool alive = true;
    size_t capacity;
    uint64_t dropped = 0;
    std::shared_ptr<std::atomic<uint64_t>> total_dropped;
    Subscriber(size_t cap, std::shared_ptr<std::atomic<uint64_t>> total)
        : capacity(cap), total_dropped(std::move(total)) {}
    bool pop(std::string& out, int timeout_ms) {
        std::unique_lock<std::mutex> lk(m);
        if (!cv.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                         [&] { return !q.empty() || !alive; }) || q.empty()) return false;
        out = std::move(q.front()); q.pop_front(); return true;
    }
    void push(const std::string& line) {
        std::lock_guard<std::mutex> lk(m);
        if (!alive) return;
        if (q.size() < capacity) q.push_back(line);
        else { ++dropped; ++*total_dropped; }
        cv.notify_one();
    }
};

class Broadcaster {
    std::mutex m_;
    std::set<std::shared_ptr<Subscriber>> subs_;
    std::deque<json> ring_;
    uint64_t seq_ = 0;
    size_t capacity_, queue_capacity_;
    std::string stream_id_;
    std::shared_ptr<std::atomic<uint64_t>> dropped_ =
        std::make_shared<std::atomic<uint64_t>>(0);
public:
    explicit Broadcaster(size_t capacity = 400, size_t queue_capacity = 10000)
        : capacity_(std::max(size_t(1), capacity)), queue_capacity_(queue_capacity) {
        stream_id_ = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())
            + "-" + std::to_string(std::random_device{}());
    }
    std::shared_ptr<Subscriber> subscribe() {
        std::lock_guard<std::mutex> lk(m_);
        auto s = std::make_shared<Subscriber>(queue_capacity_, dropped_);
        subs_.insert(s); return s;
    }
    void unsubscribe(const std::shared_ptr<Subscriber>& s) {
        std::lock_guard<std::mutex> lk(m_);
        subs_.erase(s);
        std::lock_guard<std::mutex> slk(s->m);
        s->alive = false; s->cv.notify_all();
    }
    void broadcast(const std::string& line) {
        auto event = json::parse(line, nullptr, false);
        if (!event.is_object()) event = {{"type", "raw"}, {"raw", line}};
        std::lock_guard<std::mutex> lk(m_);
        event["seq"] = ++seq_;
        event["stream_id"] = stream_id_;
        ring_.push_back(event);
        if (ring_.size() > capacity_) ring_.pop_front();
        const auto serialized = event.dump(-1, ' ', false, json::error_handler_t::replace);
        for (auto& s : subs_) s->push(serialized);
    }
    size_t count() { std::lock_guard<std::mutex> lk(m_); return subs_.size(); }
    uint64_t latest_seq() { std::lock_guard<std::mutex> lk(m_); return seq_; }
    // Cursor and events are read under ONE lock; no race between events and watermark.
    json snapshot(uint64_t since, size_t limit, const std::string& expected_stream = "") {
        std::lock_guard<std::mutex> lk(m_);
        const bool reset = (!expected_stream.empty() && expected_stream != stream_id_) || since > seq_;
        const uint64_t cursor = reset ? 0 : since;
        const uint64_t earliest = ring_.empty() ? seq_ + 1 : ring_.front()["seq"].get<uint64_t>();
        const uint64_t lost = cursor < earliest - 1 ? earliest - 1 - cursor : 0;
        json events = json::array(), subscribers = json::array();
        size_t available = 0;
        for (const auto& e : ring_) if (e["seq"].get<uint64_t>() > cursor) ++available;
        size_t skip = available > limit ? available - limit : 0;
        for (const auto& e : ring_) if (e["seq"].get<uint64_t>() > cursor) {
            if (skip) --skip; else events.push_back(e);
        }
        for (const auto& s : subs_) {
            std::lock_guard<std::mutex> slk(s->m);
            subscribers.push_back({{"queued", s->q.size()}, {"capacity", s->capacity}, {"dropped", s->dropped}});
        }
        const bool limited = limit > 0 && available > limit;
        return {{"stream_id", stream_id_}, {"latest_seq", seq_}, {"earliest_seq", earliest},
            {"count", events.size()}, {"events", events}, {"capacity", capacity_},
            {"retained", ring_.size()}, {"overwritten_total", seq_ - ring_.size()},
            {"lost_before_cursor", lost}, {"limit_truncated", limited},
            {"cursor_reset", reset}, {"cursor_only", limit == 0},
            {"truncated", reset || lost > 0 || limited},
            {"subscriber_dropped_total", dropped_->load()}, {"subscribers", subscribers},
            {"integrity_scope", "daemon_ingress"}, {"upstream_loss", "unknown"}};
    }
};
} // namespace reconbridge

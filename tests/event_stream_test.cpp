#include "event_stream.h"
#include <cassert>
#include <thread>
#include <vector>
#include <iostream>
using reconbridge::Broadcaster;
using reconbridge::json;

int main() {
    Broadcaster b(3, 2);
    auto subscriber = b.subscribe();
    b.broadcast(R"({"seq":999,"stream_id":"spoof","value":1})");
    b.broadcast(R"({"value":1})");
    auto start = b.snapshot(0, 3);
    assert(start["events"][0]["seq"] == 1);
    assert(start["events"][1]["seq"] == 2); // identical events are distinct observations
    assert(start["stream_id"] != "spoof");
    auto epoch = start["stream_id"].get<std::string>();
    b.broadcast("invalid JSON"); b.broadcast(R"({"value":4})");
    auto gap = b.snapshot(0, 3, epoch);
    assert(gap["lost_before_cursor"] == 1 && gap["truncated"] == true);
    assert(gap["subscriber_dropped_total"] == 2);
    assert(gap["events"][1]["type"] == "raw");
    auto intact = b.snapshot(1, 3, epoch);
    assert(intact["truncated"] == false && intact["latest_seq"] == 4);
    auto limited = b.snapshot(1, 1, epoch);
    assert(limited["limit_truncated"] == true && limited["events"][0]["seq"] == 4);
    assert(b.snapshot(4, 0, epoch)["truncated"] == false);
    assert(b.snapshot(4, 3, "old-daemon")["cursor_reset"] == true);
    assert(b.snapshot(999, 3, epoch)["cursor_reset"] == true);
    b.unsubscribe(subscriber);
    assert(b.snapshot(4, 0)["subscriber_dropped_total"] == 2); // survive unsubscribe
    Broadcaster next;
    assert(next.snapshot(0, 0)["stream_id"] != epoch);

    Broadcaster concurrent(20000);
    std::vector<std::thread> writers;
    for (int i = 0; i < 4; ++i) writers.emplace_back([&] {
        for (int j = 0; j < 1000; ++j) concurrent.broadcast("{}");
    });
    for (auto& t : writers) t.join();
    auto data = concurrent.snapshot(0, 20000);
    assert(data["latest_seq"] == 4000 && data["count"] == 4000);
    uint64_t seq = 0;
    for (const auto& e : data["events"]) assert(e["seq"] == ++seq);
    std::cout << "event stream tests passed\n";
}

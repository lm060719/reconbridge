#include "../m3/zygisk/native_status.h"
#include <cassert>
#include <iostream>
#include <thread>
#include <vector>
#include <atomic>

int main() {
    NativeHookStatus status;
    auto symbol = status.add({{"id", "symbol"}});
    assert(status.claim(symbol));
    // A completion callback can beat the initial API's pending return.
    assert(status.update(symbol, "installed", {{"address", 4096}}));
    assert(!status.update(symbol, "pending", {{"code", 1}}));
    assert(!status.claim(symbol));
    auto snap = status.snapshot();
    assert(snap["hooks"][0]["status"] == "installed");
    assert(snap["hooks"][0]["detail"]["address"] == 4096);

    // Concurrent library notifications must never install a slot twice.
    auto offset = status.add({{"id", "offset"}});
    std::atomic<int> winners{0};
    std::vector<std::thread> workers;
    for (int i = 0; i < 16; ++i) workers.emplace_back([&] {
        if (status.claim(offset)) {
            ++winners;
            status.update(offset, "failed", {{"code", -7}});
        }
        for (int n = 0; n < 100; ++n) {
            auto current = status.snapshot();
            assert(current["hooks"].size() == 2);
            assert(current["hooks"][0]["status"] == "installed");
        }
    });
    for (auto& thread : workers) thread.join();
    assert(winners == 1);
    assert(!status.pending(offset));
    assert(!status.update(offset, "timeout"));
    assert(status.snapshot()["hooks"][1]["detail"]["code"] == -7);

    auto missing = status.add({{"id", "missing"}});
    assert(status.pending(missing));
    status.update(missing, "timeout", {{"poll_attempts", 200}});
    assert(!status.claim(missing));
    assert(!status.update(missing, "installed"));
    status.engine({{"name", "dobby"}, {"status", "failed"}, {"error", "symbol missing"}});
    assert(status.snapshot()["engine"]["status"] == "failed");
    assert(status.snapshot()["unload_tracking"] == false);

    // ShadowHook can return a nonnull task handle while the library is pending.
    auto delayed = status.add({{"id", "delayed"}});
    status.claim(delayed);
    status.symbol_result(delayed, true, 1, 1, true, "pending");
    assert(status.pending(delayed));
    status.update(delayed, "installed", {{"address", 8192}});
    status.symbol_result(delayed, true, 1, 1, true, "pending");
    assert(status.snapshot()["hooks"][delayed]["status"] == "installed");
    auto failed = status.add({{"id", "engine_error"}});
    status.symbol_result(failed, false, 22, 1, true, "symbol not found");
    assert(status.snapshot()["hooks"][failed]["status"] == "failed");
    assert(status.snapshot()["hooks"][failed]["detail"]["code"] == 22);
    std::cout << "Native status tests passed\n";
}

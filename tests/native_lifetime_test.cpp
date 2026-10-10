#include "../m3/zygisk/native_lifetime.h"
#include "../m3/zygisk/native_live.h"
#include "../m3/zygisk/library_lifetime.h"
#include <cassert>
#include <condition_variable>
#include <iostream>
#include <thread>

int main() {
    NativeLifetime lifetime;
    std::mutex mutex; std::condition_variable changed;
    bool entered = false, leave = false;
    int removals = 0;
    std::thread caller([&] {
        auto lease = lifetime.enter(); assert(!lease.removed);
        std::unique_lock<std::mutex> lock(mutex); entered = true; changed.notify_all();
        changed.wait(lock, [&] { return leave; });
    });
    { std::unique_lock<std::mutex> lock(mutex); changed.wait(lock, [&] { return entered; }); }
    assert(lifetime.remove([&] { ++removals; return true; }) == 0 && removals == 0);
    { std::lock_guard<std::mutex> lock(mutex); leave = true; changed.notify_all(); }
    caller.join();
    assert(lifetime.remove([&] { ++removals; return false; }) == -1);
    assert(!lifetime.removed());
    assert(lifetime.remove([&] { ++removals; return true; }) == 1);
    { auto late = lifetime.enter(); assert(late.removed); }
    assert(lifetime.remove([&] { ++removals; return true; }) == 1 && removals == 2);
    { auto late = lifetime.enter(); assert(!lifetime.initialize([] { assert(false); return true; })); }
    assert(lifetime.initialize([] { return true; }) && !lifetime.removed());
    NativeLifetime throwing;
    try { auto lease = throwing.enter(); throw std::runtime_error("app exception"); } catch (...) {}
    assert(throwing.users() == 0 && throwing.remove([] { return true; }) == 1);

    NativeLiveRegistry registry;
    auto original = [](const std::array<long, 8>&) { return 12L; };
    int emitted = 0;
    auto emit = [&](const NativeSpec&, uint64_t, const std::array<long, 8>&, long) { ++emitted; };
    for (int i = 0; i < 2000; ++i) {
        auto spec = nlohmann::json{{"id", "test"}, {"lib", "fixture.so"}, {"symbol", "f" + std::to_string(i)},
            {"action", {{"type", "replace_ret"}, {"ret_value", 99}}}};
        auto change = registry.reconcile({{"targets", nlohmann::json::array({spec})}}, [](size_t slot, const NativeSpec&) { assert(slot == 0); });
        assert(change.plan->generations[0] == uint64_t(i + 1));
        auto site = change.plan->active[0]->site_key();
        assert(!registry.release(0, site)); // active slots cannot be reused
        assert(invoke_native(registry, 0, {}, original, emit, change.plan->generations[0]) == 99);
        if (i) assert(invoke_native(registry, 0, {}, original, emit, change.plan->generations[0] - 1) == 12);
        registry.reconcile({{"targets", nlohmann::json::array()}}, [](size_t, const NativeSpec&) { assert(false); });
        assert(!registry.release(0, "wrong-site") && registry.release(0, site));
    }
    assert(emitted == 2000);

    NativeLibraries libraries;
    NativeLibrary a{"/one/libsame.so", 0x1000, {{0x1100, 0x1200}}};
    NativeLibrary b{"/two/libsame.so", 0x2000, {{0x2100, 0x2200}}};
    std::vector<NativeLibrary> removed, added;
    auto remove = [&](const NativeLibrary& m) { removed.push_back(m); };
    auto add = [&](const NativeLibrary& m) { added.push_back(m); };
    libraries.sync({a, b}, remove, add);
    assert(added.size() == 2 && removed.empty());
    const auto generation = libraries.loaded().at(a.key()).generation;
    libraries.sync({a, b}, remove, add); // failed/refcount-only dlclose
    assert(removed.empty() && added.size() == 2);
    libraries.fini(a.path, a.base, remove);
    libraries.sync({a, b}, remove, add); // fini callback precedes actual unmap
    assert(!libraries.loaded().count(a.key()) && removed.size() == 1);
    libraries.arrived(a.path, a.base, remove);
    libraries.sync({a, b}, remove, add); // exact address/path reused
    assert(removed.size() == 2 && libraries.loaded().at(a.key()).generation > generation);
    libraries.sync({}, remove, add); // a dependency set may disappear together
    assert(removed.size() == 4 && libraries.loaded().empty());
    assert(a.contains(0x1100) && !a.contains(0x1200));
    std::cout << "Native drain/failure/late ingress/exception/2000 slot reuses/library generations passed\n";
}

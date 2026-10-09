#include "../m3/zygisk/native_live.h"
#include <cassert>
#include <condition_variable>
#include <iostream>
#include <thread>

using json = nlohmann::json;
static json hook(const std::string& id, const std::string& symbol, long value) {
    return {{"id", id}, {"lib", "libsample.so"}, {"symbol", symbol},
            {"action", {{"type", "replace_ret"}, {"ret_value", value}}}};
}
static json config(json targets) { return {{"targets", std::move(targets)}}; }

int main() {
    NativeLiveRegistry registry;
    int allocations = 0, emits = 0;
    auto prepare = [&](size_t, const NativeSpec&) { ++allocations; };
    auto original = [](const std::array<long, 8>& args) { return args[0] + 10; };
    auto emit = [&](const NativeSpec&, uint64_t, const std::array<long, 8>&, long) { ++emits; };
    auto first = config(json::array({hook("h1", "foo", 101)}));
    auto one = registry.reconcile(first, prepare);
    assert(one.plan->revision == 1 && allocations == 1);
    assert(invoke_native(registry, 0, {1}, original, emit) == 101 && emits == 1);
    assert(!registry.reconcile(first, prepare).changed && allocations == 1);

    // A call paused inside the original must keep its own old generation.
    std::mutex lock;
    std::condition_variable ready;
    bool entered = false, release = false;
    long old_result = 0;
    uint64_t old_revision = 0;
    std::thread inflight([&] {
        old_result = invoke_native(registry, 0, {1}, [&](const std::array<long, 8>&) {
            std::unique_lock<std::mutex> guard(lock);
            entered = true; ready.notify_all();
            ready.wait(guard, [&] { return release; });
            return 11L;
        }, [&](const NativeSpec& spec, uint64_t revision, const std::array<long, 8>&, long result) {
            old_revision = revision;
            assert(spec.ret_value == 101 && result == 11);
        });
    });
    { std::unique_lock<std::mutex> guard(lock); ready.wait(guard, [&] { return entered; }); }
    registry.reconcile(config(json::array({hook("renamed", "foo", 202)})), prepare);
    assert(allocations == 1);
    assert(invoke_native(registry, 0, {1}, original, emit) == 202);
    registry.reconcile(config(json::array()), prepare);
    const int before = emits;
    assert(invoke_native(registry, 0, {1}, original, emit) == 11 && emits == before);
    { std::lock_guard<std::mutex> guard(lock); release = true; ready.notify_all(); }
    inflight.join();
    assert(old_result == 101 && old_revision == 1);
    registry.reconcile(first, prepare);
    assert(allocations == 1 && invoke_native(registry, 0, {1}, original, emit) == 101);

    // A same-ID move publishes both deactivation and activation in one plan.
    registry.reconcile(config(json::array({hook("h1", "bar", 303)})), prepare);
    assert(allocations == 2);
    assert(invoke_native(registry, 0, {1}, original, emit) == 11);
    assert(invoke_native(registry, 1, {1}, original, emit) == 303);

    auto stable = registry.snapshot();
    for (const auto& bad : std::vector<json>{
        config(json::array({hook("same", "a", 1), hook("same", "b", 2)})),
        config(json::array({hook("a", "same", 1), hook("b", "same", 2)})),
        config(json::array({{{"id", "x"}, {"lib", "x.so"}, {"offset", "0xBADsuffix"}}})),
        config(json::array({{{"id", "x"}, {"lib", "x.so"}, {"offset", -1}}})),
        config(json::array({{{"id", "x"}, {"lib", "x.so"}, {"offset", 1.5}}})),
        config(json::array({{{"id", "x"}, {"lib", "x.so"}, {"symbol", "a"},
                            {"capture", {{"args", json::array({{{"index", 0}, {"type", "float"}}})}}}}})),
        config(json::array({{{"id", "x"}, {"lib", "x.so"}, {"symbol", "a"},
                            {"action", {{"type", "replace_arg"}, {"arg_overrides", json::array({{{"index", 8}, {"value", 1}}})}}}}})),
        config(json::array({42})), json::object()
    }) {
        bool rejected = false;
        try { registry.reconcile(bad, prepare); } catch (const std::exception&) { rejected = true; }
        assert(rejected && registry.snapshot() == stable && allocations == 2);
    }

    // Full-width overrides and argument replacement use the actual dispatch helper.
    auto args_hook = hook("args", "bar", 0);
    args_hook["action"] = {{"type", "replace_arg"}, {"arg_overrides", json::array({{{"index", 0}, {"value", 20}}})}};
    registry.reconcile(config(json::array({args_hook})), prepare);
    assert(invoke_native(registry, 1, {1}, original, emit) == 30);
    args_hook["action"]["arg_overrides"][0]["value"] = int64_t(1) << 40;
    assert(parse_native_spec(args_hook, 0).arg_overrides[0].second == (int64_t(1) << 40));

    // Capacity is lifetime hook points. A failed transaction allocates nothing;
    // repeated remove/re-add of an existing point does not consume capacity.
    NativeLiveRegistry bounded;
    json many = json::array();
    for (int i = 0; i < 65; ++i) many.push_back(hook(std::to_string(i), "f" + std::to_string(i), i));
    int prepared = 0;
    auto count = [&](size_t, const NativeSpec&) { ++prepared; };
    bool rejected = false;
    try { bounded.reconcile(config(many), count); } catch (const std::exception&) { rejected = true; }
    assert(rejected && prepared == 0 && bounded.snapshot()->revision == 0);
    many.erase(64);
    bounded.reconcile(config(many), count);
    for (int i = 0; i < 100; ++i) {
        bounded.reconcile(config(json::array()), count);
        bounded.reconcile(config(many), count);
    }
    assert(prepared == 64);

    // Readers observe complete generations, never partially switched target sets.
    NativeLiveRegistry concurrent;
    std::atomic<bool> done{false};
    std::thread reader([&] {
        while (!done.load()) {
            auto plan = concurrent.snapshot();
            if (plan->active[0]) {
                assert(plan->active[1]);
                assert(plan->active[0]->ret_value == plan->active[1]->ret_value);
            }
        }
    });
    for (int i = 0; i < 1000; ++i)
        concurrent.reconcile(config(json::array({hook("a", "a", i), hook("b", "b", i)})),
                             [](size_t, const NativeSpec&) {});
    done = true; reader.join();
    std::cout << "Native live configuration/dispatch tests passed\n";
}

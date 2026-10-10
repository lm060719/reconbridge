#include "../m3/zygisk/native_abi.h"
#include "../m3/zygisk/native_lifetime.h"
#include "../m3/zygisk/native_gateway.h"
#include <cassert>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <vector>

#ifdef RB_REAL_ENGINE
extern "C" int DobbyHook(void*, void*, void**);
extern "C" int DobbyDestroy(void*);
#endif
struct Context : NativeSpec {
    NativeLifetime lifetime;
    std::atomic<bool> module_valid{true};
    size_t slot = 0;
    uint64_t generation = 0;
    uintptr_t address = 0;
    void* orig = nullptr;
};
static NativeLiveRegistry registry;
static int emitted = 0;
extern "C" void rb_native_dispatch(uintptr_t context, NativeFrame* frame) {
    invoke_native_generation(registry, *reinterpret_cast<Context*>(context), *frame,
        [](const NativeSpec&, uint64_t, const std::array<long, 8>&, long) { ++emitted; });
}
__attribute__((noinline)) static long sample(long value) {
    if (value < 0) throw std::runtime_error("fixture exception");
    return value + 7;
}
__attribute__((noinline)) static double mixed(long a, float b, double c) { return a + b + c; }
int main() {
    using json = nlohmann::json;
    std::vector<std::unique_ptr<Context>> contexts;
    std::vector<void*> gateways;
    for (int i = 0; i < 100; ++i) {
        json target = {{"id", "sample"}, {"lib", "fixture.so"}, {"symbol", "sample" + std::to_string(i)},
            {"signature", {{"args", {"int64"}}, {"ret", "int64"}}},
            {"action", {{"type", "replace_ret"}, {"ret_value", 99}}}};
        auto context = std::make_unique<Context>();
        registry.reconcile({{"targets", json::array({target})}}, [&](size_t slot, const NativeSpec& spec) {
            assert(slot == 0); static_cast<NativeSpec&>(*context) = spec;
        });
        context->generation = registry.snapshot()->generations[0];
        context->address = reinterpret_cast<uintptr_t>(&sample);
        context->orig = reinterpret_cast<void*>(&sample);
        auto gateway = native_gateway(context.get());
        unsigned char original_bytes[16]; std::memcpy(original_bytes, reinterpret_cast<void*>(&sample), sizeof(original_bytes));
#ifdef RB_REAL_ENGINE
        assert(DobbyHook(reinterpret_cast<void*>(&sample), gateway, &context->orig) == 0);
        volatile auto actual = &sample; assert(actual(3) == 99);
#endif
        auto proxy = reinterpret_cast<long(*)(long)>(gateway);
        assert(proxy(3) == 99);
        try { proxy(-1); assert(false); } catch (const std::runtime_error&) {}
        assert(context->lifetime.users() == 0);
        registry.reconcile({{"targets", json::array()}}, [](size_t, const NativeSpec&) { assert(false); });
        assert(context->lifetime.remove([&] {
#ifdef RB_REAL_ENGINE
            return DobbyDestroy(reinterpret_cast<void*>(&sample)) == 0;
#else
            return true;
#endif
        }) == 1);
        assert(std::memcmp(original_bytes, reinterpret_cast<void*>(&sample), sizeof(original_bytes)) == 0);
        context->orig = reinterpret_cast<void*>(1); // freed trampoline must never be used by a late gateway
        assert(proxy(3) == 10);
        assert(registry.release(0, context->site_key()));
        contexts.push_back(std::move(context)); gateways.push_back(gateway);
    }
    // Old gateways keep their own signature and original even after slot reuse.
    auto fp = std::make_unique<Context>();
    json target = {{"id", "mixed"}, {"lib", "fixture.so"}, {"symbol", "mixed"},
        {"signature", {{"args", {"int64", "float", "double"}}, {"ret", "double"}}}};
    registry.reconcile({{"targets", json::array({target})}}, [&](size_t, const NativeSpec& spec) { static_cast<NativeSpec&>(*fp) = spec; });
    fp->generation = registry.snapshot()->generations[0]; fp->orig = reinterpret_cast<void*>(&mixed);
    fp->address = reinterpret_cast<uintptr_t>(&mixed);
    assert(reinterpret_cast<double(*)(long,float,double)>(native_gateway(fp.get()))(2,1.5f,3.25) == 6.75);
    for (auto gateway : gateways) assert(reinterpret_cast<long(*)(long)>(gateway)(3) == 10);
    contexts.front()->module_valid = false;
    assert(reinterpret_cast<long(*)(long)>(gateways.front())(3) == 0);
    std::cout << "Native RX gateways: generation reuse, late entry, mixed ABI, exception unwind, restored bytes passed\n";
}

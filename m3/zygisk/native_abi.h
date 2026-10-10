#pragma once
#include "native_live.h"
#include <cstddef>
#include <cstdio>

// Exactly matches native_bridge.S. gp[6..7] hold x86_64 spilled integer args;
// ARM64 has eight integer registers and no spills within our eight-arg bound.
struct alignas(16) NativeFrame {
    uint64_t gp[8];
    uint64_t fp[8];
    uint64_t result_gp;
    uint64_t result_fp;
    const uint64_t* stack;
};
static_assert(sizeof(long) == 8 && sizeof(void*) == 8, "requires a 64-bit LP64 ABI");
static_assert(sizeof(float) == 4 && sizeof(double) == 8 && std::numeric_limits<float>::is_iec559 &&
              std::numeric_limits<double>::is_iec559, "requires IEEE binary32/binary64");
static_assert(offsetof(NativeFrame, fp) == 64 && offsetof(NativeFrame, result_gp) == 128 &&
              offsetof(NativeFrame, result_fp) == 136 && offsetof(NativeFrame, stack) == 144 &&
              sizeof(NativeFrame) == 160, "assembly frame layout changed");

extern "C" void rb_native_call(void* original, NativeFrame* frame);

inline void native_load_stack(const NativeSpec& signature, NativeFrame& frame) {
#if defined(__x86_64__)
    size_t integers = 0;
    for (size_t i = 0; i < signature.signature_count; ++i)
        if (!native_floating(signature.signature_args[i])) ++integers;
    frame.gp[6] = frame.gp[7] = 0;
    for (size_t i = 6; i < integers; ++i) frame.gp[i] = frame.stack[i - 6];
#else
    (void)signature; (void)frame;
#endif
}

inline std::array<long, 8> native_logical_args(const NativeSpec& signature, const NativeFrame& frame) {
    std::array<long, 8> args{};
    size_t integer = 0, floating = 0;
    for (size_t i = 0; i < signature.signature_count; ++i)
        args[i] = static_cast<long>(native_floating(signature.signature_args[i]) ? frame.fp[floating++] : frame.gp[integer++]);
    return args;
}
inline void native_store_args(const NativeSpec& signature, NativeFrame& frame, const std::array<long, 8>& args) {
    size_t integer = 0, floating = 0;
    for (size_t i = 0; i < signature.signature_count; ++i) {
        auto& destination = native_floating(signature.signature_args[i]) ? frame.fp[floating++] : frame.gp[integer++];
        destination = static_cast<uint64_t>(args[i]);
    }
}

template<class Emit>
void invoke_native_frame(const NativeLiveRegistry& registry, size_t slot, const NativeSpec& retained_signature,
                         void* original, NativeFrame& frame, Emit emit, uint64_t generation = 0) {
    native_load_stack(retained_signature, frame);
    const auto logical = native_logical_args(retained_signature, frame);
    const long result = invoke_native(registry, slot, logical,
        [&](const std::array<long, 8>& args) {
            native_store_args(retained_signature, frame, args);
            frame.result_gp = frame.result_fp = 0;
            if (original) rb_native_call(original, &frame);
            return static_cast<long>(native_floating(retained_signature.signature_ret) ? frame.result_fp : frame.result_gp);
        }, emit, generation);
    if (native_floating(retained_signature.signature_ret)) frame.result_fp = static_cast<uint64_t>(result);
    else frame.result_gp = static_cast<uint64_t>(result);
}

template<class Context, class Emit>
void invoke_native_generation(const NativeLiveRegistry& registry, Context& target, NativeFrame& frame, Emit emit) {
    auto lease = target.lifetime.enter();
    if (!target.module_valid.load()) { frame.result_gp = frame.result_fp = 0; return; }
    void* original = lease.removed ? reinterpret_cast<void*>(target.address) : target.orig;
    invoke_native_frame(registry, target.slot, target, original, frame, emit,
                        lease.removed ? UINT64_MAX : target.generation);
}

inline nlohmann::json native_float_capture(ArgType type, uint64_t bits) {
    double number;
    char raw[19];
    if (type == T_FLOAT) {
        const uint32_t low = static_cast<uint32_t>(bits);
        float value; std::memcpy(&value, &low, sizeof(value)); number = value;
        std::snprintf(raw, sizeof(raw), "0x%08x", static_cast<unsigned>(low));
    } else {
        std::memcpy(&number, &bits, sizeof(number));
        std::snprintf(raw, sizeof(raw), "0x%016llx", static_cast<unsigned long long>(bits));
    }
    nlohmann::json capture = {{"type", type == T_FLOAT ? "float" : "double"}, {"bits", raw}};
    capture["value"] = std::isfinite(number) ? nlohmann::json(number) : nlohmann::json(nullptr);
    if (!std::isfinite(number)) capture["special"] = std::isnan(number) ? "nan" : std::signbit(number) ? "-inf" : "+inf";
    return capture;
}

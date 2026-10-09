#include "../m3/zygisk/native_abi.h"
#include <cassert>
#include <iostream>
#include <stdexcept>

using json = nlohmann::json;
static NativeLiveRegistry registry;
static std::array<NativeSpec, 64> retained;
static std::array<void*, 64> originals{};
static std::array<long, 8> observed;
static long observed_ret;
static int emitted = 0;
extern "C" void rb_proxy_0();
extern "C" void rb_proxy_1();
extern "C" void rb_proxy_2();
extern "C" void rb_proxy_3();
extern "C" void rb_proxy_4();
extern "C" void rb_proxy_5();
extern "C" void rb_proxy_6();
extern "C" void rb_proxy_7();
extern "C" void rb_native_dispatch(int slot, NativeFrame* frame) {
    invoke_native_frame(registry, slot, retained.at(slot), originals.at(slot), *frame,
        [](const NativeSpec&, uint64_t, const std::array<long, 8>& args, long result) {
            observed = args; observed_ret = result; ++emitted;
        });
}
static json target(const char* name, json args, const char* ret) {
    return {{"id", name}, {"lib", "test.so"}, {"symbol", name},
            {"signature", {{"args", args}, {"ret", ret}}}};
}
static void configure(const json& targets) {
    registry.reconcile({{"targets", targets}}, [](size_t slot, const NativeSpec& spec) { retained[slot] = spec; });
}
template<class F> static F proxy(void (*entry)()) { return reinterpret_cast<F>(entry); }
__attribute__((noinline)) static double mixed(long a, float b, double c, const long* p) { return a + b * 2 + c * 3 + *p; }
static bool disable_in_original = false;
__attribute__((noinline)) static float scalar(float a) {
    if (disable_in_original) { disable_in_original = false; configure(json::array()); }
    return a;
}
__attribute__((noinline)) static double identity(double a) { return a; }
__attribute__((noinline)) static long spill_fp(long a,long b,float c,long d,long e,long f,long g,long h) {
    return a + 2*b + long(3*c) + 4*d + 5*e + 6*f + 7*g + 8*h;
}
__attribute__((noinline)) static double all_fp(float a, double b, float c, double d, float e, double f, float g, double h) {
    return a + 2*b + 3*c + 4*d + 5*e + 6*f + 7*g + 8*h;
}
__attribute__((noinline)) static long all_gp(long a,long b,long c,long d,long e,long f,long g,long h) {
    return a + 2*b + 3*c + 4*d + 5*e + 6*f + 7*g + 8*h;
}
__attribute__((noinline)) static double no_args() { return -4.25; }
__attribute__((noinline)) static double throws(double) { throw std::runtime_error("unwind"); }

int main() {
    auto mix = target("mixed", {"int64", "float", "double", "ptr"}, "double");
    auto flt = target("float", {"float"}, "float");
    auto fp8 = target("fp8", {"float","double","float","double","float","double","float","double"}, "double");
    auto gp8 = target("gp8", {"int64","int64","int64","int64","int64","int64","int64","int64"}, "int64");
    auto zero = target("zero", json::array(), "double");
    auto exc = target("throws", {"double"}, "double");
    auto ident = target("identity", {"double"}, "double");
    auto spill = target("spill", {"int64","int64","float","int64","int64","int64","int64","int64"}, "int64");
    json targets = json::array({mix, flt, fp8, gp8, zero, exc, ident, spill});
    configure(targets);
    originals = {(void*)&mixed, (void*)&scalar, (void*)&all_fp, (void*)&all_gp, (void*)&no_args, (void*)&throws, (void*)&identity, (void*)&spill_fp};
    auto call_mix = proxy<decltype(&mixed)>(&rb_proxy_0);
    auto call_float = proxy<decltype(&scalar)>(&rb_proxy_1);
    auto call_fp8 = proxy<decltype(&all_fp)>(&rb_proxy_2);
    auto call_gp8 = proxy<decltype(&all_gp)>(&rb_proxy_3);
    auto call_zero = proxy<decltype(&no_args)>(&rb_proxy_4);
    long pointee = 7;
    assert(call_mix(2, 1.25f, 2.5, &pointee) == 19);
    assert(observed[0] == 2 && uint64_t(observed[1]) % (1ULL<<32) == native_fp_bits(T_FLOAT, 1.25));
    assert(uint64_t(observed[2]) == native_fp_bits(T_DOUBLE, 2.5));
    assert(observed[3] == reinterpret_cast<long>(&pointee));
    assert(uint64_t(observed_ret) == native_fp_bits(T_DOUBLE, 19));
    assert(call_fp8(1,2,3,4,5,6,7,8) == 204);
    assert(call_gp8(1,2,3,4,5,6,7,8) == 204);
    assert(call_zero() == -4.25);
    assert(proxy<decltype(&spill_fp)>(&rb_proxy_7)(1,2,3,4,5,6,7,8) == 204);

    // Logical indices must select independent GP/FP banks, including GP spills.
    targets[0]["action"] = {{"type", "replace_arg"}, {"arg_overrides", json::array({
        {{"index",0},{"value",10}}, {{"index",1},{"value",3.5}}, {{"index",2},{"value",-2.25}}})}};
    targets[3]["action"] = {{"type", "replace_arg"}, {"arg_overrides", json::array({{{"index",7},{"value",10}}})}};
    configure(targets);
    assert(call_mix(2,1.25f,2.5,&pointee) == 17.25);
    assert(call_gp8(1,2,3,4,5,6,7,8) == 220);
    targets[0]["action"] = {{"type", "replace_ret"}, {"ret_value", -123.125}};
    targets[1]["action"] = {{"type", "replace_ret"}, {"ret_value", 1.1}};
    configure(targets);
    assert(call_mix(2,1.25f,2.5,&pointee) == -123.125);
    assert(uint64_t(observed_ret) == native_fp_bits(T_DOUBLE,19));
    assert(call_float(2) == 1.1f);
    disable_in_original = true;
    assert(call_float(2) == 1.1f); // in-flight call keeps the old return replacement
    assert(call_float(2) == 2); // next call sees the disabled plan
    targets[1]["action"] = {{"type", "replace_arg"}, {"arg_overrides", json::array({{{"index",0},{"value",-0.0}}})}};
    configure(targets);
    assert(std::signbit(call_float(2)));

    // Disabled sites retain their ABI and preserve non-finite values bit-for-bit.
    configure(json::array());
    const int count = emitted;
    assert(call_mix(2,1.25f,2.5,&pointee) == 19 && call_fp8(1,2,3,4,5,6,7,8) == 204);
    assert(call_gp8(1,2,3,4,5,6,7,8) == 204 && call_zero() == -4.25);
    for (uint32_t bits : {0x80000000u, 0x7fc12345u, 0x7f800000u, 0xff800000u}) {
        float value; std::memcpy(&value, &bits, 4);
        float result = call_float(value); uint32_t actual; std::memcpy(&actual, &result, 4);
        assert(actual == bits);
    }
    for (uint64_t bits : {0x8000000000000000ULL, 0x7ff812345678abcdULL, 0x7ff0000000000000ULL, 0xfff0000000000000ULL}) {
        double value; std::memcpy(&value, &bits, 8);
        double result = proxy<decltype(&identity)>(&rb_proxy_6)(value);
        uint64_t actual; std::memcpy(&actual, &result, 8);
        assert(actual == bits);
    }
    assert(emitted == count);
    auto changed = targets; changed[0]["signature"]["args"][1] = "double";
    bool rejected = false;
    try { configure(changed); } catch (const std::invalid_argument&) { rejected = true; }
    assert(rejected && !registry.snapshot()->active[0]);
    configure(targets);
    assert(call_mix(2,1.25f,2.5,&pointee) == -123.125);

    // Unwind through both real assembly frames back into the caller.
    bool caught = false;
    try { proxy<decltype(&throws)>(&rb_proxy_5)(1.5); }
    catch (const std::runtime_error& e) { caught = std::string(e.what()) == "unwind"; }
    assert(caught);

    auto negzero = native_float_capture(T_FLOAT, 0x80000000);
    assert(negzero["bits"] == "0x80000000" && std::signbit(negzero["value"].get<double>()));
    auto nan = native_float_capture(T_FLOAT, 0x7fc12345);
    assert(nan["value"].is_null() && nan["special"] == "nan" && nan["bits"] == "0x7fc12345");
    auto inf = native_float_capture(T_DOUBLE, 0xfff0000000000000ULL);
    assert(inf["value"].is_null() && inf["special"] == "-inf");
    assert(json::parse(inf.dump()) == inf);
    std::cout << "Native scalar ABI: mixed registers, FP8, GP8/spills, replacements, passthrough, raw bits, unwind passed\n";
}

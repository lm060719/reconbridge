// Test the observer against a fake JNI table; no Android process is hooked.
#include <jni.h>
#include "third_party/json.hpp"
#include <algorithm>
#include <cstring>
#include <cstdio>
#include <string>
#include <vector>
#include <cassert>
#include <iostream>
#include <ctime>
#include <unordered_map>
#include <mutex>

using json = nlohmann::json;
static std::vector<json> events;
static bool pending = false, observer_error = false;
static int cleared = 0, original_calls = 0;
static jint original_result = JNI_OK;
static std::string g_package = "com.example.app";
static bool safe_read(const void* p, void* out, size_t n) { if (!p) return false; memcpy(out, p, n); return true; }
static std::string read_cstr(const void* p, int max) { return p ? std::string(static_cast<const char*>(p)).substr(0, max) : ""; }
static void send_event(const std::string& line) { events.push_back(json::parse(line)); }
struct Dl_info { const char* dli_fname; void* dli_fbase; const char* dli_sname; void* dli_saddr; };
static int dladdr(const void*, Dl_info* out) { *out = {"/test/libsample.so", reinterpret_cast<void*>(0x1000), "nativeFoo", nullptr}; return 1; }
static long fake_syscall(int) { return 123; }
static int fake_getpid() { return 42; }
#define syscall fake_syscall
#define getpid fake_getpid
#define __NR_gettid 0
#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
static int clock_gettime(int, timespec* value) { value->tv_sec = 100; value->tv_nsec = 0; return 0; }
#endif
// Engine is simulated; the test never installs a native hook.
static int fake_hook(void*, void*, void**) { return -1; }
static auto db_hook = fake_hook;
#include "../m3/zygisk/jni_observer.h"

static jint JNICALL original(JNIEnv*, jclass, const JNINativeMethod*, jint) { ++original_calls; return original_result; }
static jboolean JNICALL exception_check(JNIEnv*) { return pending ? JNI_TRUE : JNI_FALSE; }
static void JNICALL exception_clear(JNIEnv*) { ++cleared; pending = false; }
static jobject JNICALL call_object(JNIEnv*, jobject, jmethodID, va_list) {
    if (observer_error) { pending = true; return nullptr; }
    return reinterpret_cast<jobject>(0x1);
}
static const char* JNICALL string_chars(JNIEnv*, jstring, jboolean*) { return "com.example.Native"; }
static void JNICALL release_chars(JNIEnv*, jstring, const char*) {}
static void JNICALL delete_ref(JNIEnv*, jobject) {}
static std::unordered_map<jweak, jobject> weak_refs;
static uintptr_t next_ref = 100;
static jobject collected = nullptr;
static jobject canonical(jobject obj) { return obj == reinterpret_cast<jobject>(0x22) ? reinterpret_cast<jobject>(0x2) : obj; }
static jweak JNICALL new_weak(JNIEnv*, jobject obj) {
    auto ref = reinterpret_cast<jweak>(++next_ref); weak_refs[ref] = canonical(obj); return ref;
}
static jobject JNICALL new_local(JNIEnv*, jobject obj) {
    auto value = weak_refs.at(static_cast<jweak>(obj));
    return value == collected ? nullptr : value;
}
static void JNICALL delete_weak(JNIEnv*, jweak ref) { weak_refs.erase(ref); }
static jboolean JNICALL same(JNIEnv*, jobject a, jobject b) { return canonical(a) == canonical(b); }
static jint JNICALL unregister_original(JNIEnv*, jclass) { return original_result; }

int main() {
    JNINativeInterface_ table{};
    table.ExceptionCheck = exception_check; table.ExceptionClear = exception_clear;
    table.CallObjectMethodV = call_object; table.GetStringUTFChars = string_chars;
    table.ReleaseStringUTFChars = release_chars; table.DeleteLocalRef = delete_ref;
    table.NewWeakGlobalRef = new_weak; table.NewLocalRef = new_local;
    table.DeleteWeakGlobalRef = delete_weak; table.IsSameObject = same;
    JNIEnv env{&table};
    g_register_original = original;
    g_unregister_original = unregister_original;
    g_class_name = reinterpret_cast<jmethodID>(0x1);
    g_jni_hook_id = "__rb_jni";
    JNINativeMethod method{const_cast<char*>("foo"), const_cast<char*>("(I)I"), reinterpret_cast<void*>(0x1234)};
    auto clazz = reinterpret_cast<jclass>(0x2);
    assert(observe_register_natives(&env, clazz, &method, 1) == JNI_OK);
    assert(original_calls == 1 && events.size() == 1);
    assert(events[0]["class"] == "com.example.Native" && events[0]["offset"] == "0x234");
    assert(events[0]["signature"] == "(I)I");
    const auto first_id = events[0]["class_id"];
    assert(!first_id.get<std::string>().empty());

    pending = true; original_result = -1;
    assert(observe_register_natives(&env, clazz, &method, 1) == -1);
    assert(pending && cleared == 0 && events.size() == 1); // Preserve VM failure/exception.
    pending = false; original_result = 0; observer_error = true;
    assert(observe_register_natives(&env, clazz, &method, 1) == 0);
    assert(!pending && cleared == 1 && events.back()["class"] == ""); // Only our exception cleared.
    observer_error = false; g_in_jni_observer = true;
    const auto before = events.size();
    assert(observe_register_natives(&env, clazz, &method, 1) == 0);
    assert(events.size() == before && original_calls == 4); // Reentrant observer still calls original.
    g_in_jni_observer = false;
    observe_register_natives(&env, reinterpret_cast<jclass>(0x22), &method, 1);
    assert(events.back()["class_id"] == first_id); // Distinct JNI handles, same object.
    observe_register_natives(&env, reinterpret_cast<jclass>(0x3), &method, 1);
    assert(events.back()["class_id"] != first_id && events.back()["class"] == events[0]["class"]);
    const auto second_id = events.back()["class_id"];
    assert(observe_unregister_natives(&env, clazz) == JNI_OK);
    assert(events.back()["type"] == "jni_unregistration" && events.back()["class_id"] == first_id);
    const auto unregistered = events.size();
    pending = true; original_result = -1;
    assert(observe_unregister_natives(&env, clazz) == -1 && pending && events.size() == unregistered);
    assert(cleared == 1); // Never clear the original VM exception.
    pending = false; original_result = JNI_OK;
    collected = reinterpret_cast<jobject>(0x3);
    observe_unregister_natives(&env, clazz);
    assert(events[events.size()-2]["type"] == "jni_class_collected");
    assert(events[events.size()-2]["class_id"] == second_id && weak_refs.size() == 1);
    collected = nullptr;
    observe_register_natives(&env, reinterpret_cast<jclass>(0x3), &method, 1);
    assert(events.back()["class_id"] != second_id); // GC/reuse never recycles IDs.
    pending = true;
    const auto before_pending = events.size();
    assert(observe_register_natives(&env, clazz, &method, 1) == JNI_OK && pending);
    assert(observe_unregister_natives(&env, clazz) == JNI_OK && pending);
    assert(events.size() == before_pending && cleared == 1);
    pending = false;
    g_in_jni_observer = true;
    assert(observe_unregister_natives(&env, clazz) == JNI_OK && events.size() == before_pending);
    g_in_jni_observer = false;
    for (uintptr_t i = 0; i < 1024; ++i)
        observe_register_natives(&env, reinterpret_cast<jclass>(10000+i), &method, 1);
    assert(g_jni_classes.size() == 1024 && weak_refs.size() == 1024);
    assert(events.back()["class_id"] == "" && events.back()["class_identity_verified"] == false);
    std::cout << "JNI observer tests passed\n";
}

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

int main() {
    JNINativeInterface_ table{};
    table.ExceptionCheck = exception_check; table.ExceptionClear = exception_clear;
    table.CallObjectMethodV = call_object; table.GetStringUTFChars = string_chars;
    table.ReleaseStringUTFChars = release_chars; table.DeleteLocalRef = delete_ref;
    JNIEnv env{&table};
    g_register_original = original;
    g_class_name = reinterpret_cast<jmethodID>(0x1);
    g_jni_hook_id = "__rb_jni";
    JNINativeMethod method{const_cast<char*>("foo"), const_cast<char*>("(I)I"), reinterpret_cast<void*>(0x1234)};
    auto clazz = reinterpret_cast<jclass>(0x2);
    assert(observe_register_natives(&env, clazz, &method, 1) == JNI_OK);
    assert(original_calls == 1 && events.size() == 1);
    assert(events[0]["class"] == "com.example.Native" && events[0]["offset"] == "0x234");
    assert(events[0]["signature"] == "(I)I");

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
    std::cout << "JNI observer tests passed\n";
}

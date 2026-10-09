// Included after the transport/engine helpers in module.cpp.
// Observes future registration lifecycle; never changes VM results or exceptions.
#include <mutex>
#include <vector>
static jint (*g_register_original)(JNIEnv*, jclass, const JNINativeMethod*, jint) = nullptr;
static jint (*g_unregister_original)(JNIEnv*, jclass) = nullptr;
static std::mutex g_jni_identity_mutex;
static std::vector<std::pair<jweak, uint64_t>> g_jni_classes;
static uint64_t g_jni_next_class = 0, g_jni_sequence = 0;
static jmethodID g_class_name = nullptr;
static std::string g_jni_hook_id;
static std::string g_jni_instance;
static thread_local bool g_in_jni_observer = false;

static std::string pointer_hex(uintptr_t value) {
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "0x%llx", (unsigned long long)value);
    return buffer;
}

// The caller holds g_jni_identity_mutex. Weak references distinguish same-named
// classes without pinning their loaders. IDs never repeat during this process.
static json jni_event(const char* type, const char* source) {
    timespec ts{}; clock_gettime(CLOCK_REALTIME, &ts);
    return {{"type", type}, {"source", source}, {"observer_version", 2},
        {"hook_id", g_jni_hook_id}, {"package", g_package}, {"pid", getpid()},
        {"tid", syscall(__NR_gettid)}, {"process_instance", g_jni_instance},
        {"observation_seq", ++g_jni_sequence},
        {"ts", int64_t(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000}};
}
static std::string jni_class_id(JNIEnv* env, jclass clazz) {
    std::string found;
    for (auto it = g_jni_classes.begin(); it != g_jni_classes.end();) {
        auto local = env->NewLocalRef(it->first);
        if (env->ExceptionCheck()) { env->ExceptionClear(); return ""; }
        if (!local) {
            auto event = jni_event("jni_class_collected", "weak_class_reference");
            event["class_id"] = std::to_string(it->second);
            send_event(event.dump());
            env->DeleteWeakGlobalRef(it->first);
            it = g_jni_classes.erase(it);
        } else {
            if (env->IsSameObject(local, clazz)) found = std::to_string(it->second);
            env->DeleteLocalRef(local); ++it;
        }
    }
    if (!found.empty()) return found;
    if (g_jni_classes.size() >= 1024) return "";
    auto weak = env->NewWeakGlobalRef(clazz);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return ""; }
    if (!weak) return "";
    const auto id = ++g_jni_next_class;
    try { g_jni_classes.push_back({weak, id}); }
    catch (...) { env->DeleteWeakGlobalRef(weak); throw; }
    return std::to_string(id);
}
static std::string jni_class_name(JNIEnv* env, jclass clazz) {
    std::string result;
    auto name = static_cast<jstring>(env->CallObjectMethod(clazz, g_class_name));
    if (env->ExceptionCheck()) env->ExceptionClear();
    else if (name) {
        const char* value = env->GetStringUTFChars(name, nullptr);
        if (value) {
            try { result = value; }
            catch (...) { env->ReleaseStringUTFChars(name, value); env->DeleteLocalRef(name); throw; }
            env->ReleaseStringUTFChars(name, value);
        }
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    if (name) env->DeleteLocalRef(name);
    return result;
}

static jint observe_register_natives(JNIEnv* env, jclass clazz,
                                    const JNINativeMethod* methods, jint count) {
    // Call the real VM first. Failed registrations are not evidence of a binding.
    const jint rc = g_register_original(env, clazz, methods, count);
    if (rc != JNI_OK || g_in_jni_observer || env->ExceptionCheck()) return rc;
    g_in_jni_observer = true;
    try {
        std::lock_guard<std::mutex> guard(g_jni_identity_mutex);
        const auto class_id = jni_class_id(env, clazz);
        const auto class_name = jni_class_name(env, clazz);
        const int captured = std::min(std::max(int(count), 0), 1024);
        for (int i = 0; i < captured; ++i) {
            JNINativeMethod method{};
            if (!safe_read(methods + i, &method, sizeof(method))) break;
            Dl_info info{};
            const bool resolved = dladdr(method.fnPtr, &info) != 0 && info.dli_fbase;
            json event = jni_event("jni_registration", "RegisterNatives");
            event.update(json({{"class_id", class_id},
                {"class_identity_verified", !class_id.empty()},
                {"class", class_name}, {"method", read_cstr(method.name, 1024)},
                {"signature", read_cstr(method.signature, 4096)},
                {"address", pointer_hex(reinterpret_cast<uintptr_t>(method.fnPtr))},
                {"module", resolved && info.dli_fname ? info.dli_fname : ""},
                {"module_base", resolved ? json(pointer_hex(reinterpret_cast<uintptr_t>(info.dli_fbase))) : json(nullptr)},
                {"offset", resolved ? json(pointer_hex(reinterpret_cast<uintptr_t>(method.fnPtr) -
                    reinterpret_cast<uintptr_t>(info.dli_fbase))) : json(nullptr)},
                {"symbol", resolved && info.dli_sname ? info.dli_sname : ""},
                {"registration_count", count}, {"registration_truncated", count > captured},
                {"result", rc}}));
            send_event(event.dump(-1, ' ', false, json::error_handler_t::replace));
        }
    } catch (...) {
        // Observation must not unwind through the VM or change the registered binding.
    }
    g_in_jni_observer = false;
    return rc;
}

static jint observe_unregister_natives(JNIEnv* env, jclass clazz) {
    const jint rc = g_unregister_original(env, clazz);
    if (rc != JNI_OK || g_in_jni_observer || env->ExceptionCheck()) return rc;
    g_in_jni_observer = true;
    try {
        std::lock_guard<std::mutex> guard(g_jni_identity_mutex);
        const auto class_id = jni_class_id(env, clazz);
        const auto class_name = jni_class_name(env, clazz);
        auto event = jni_event("jni_unregistration", "UnregisterNatives");
        event.update(json({{"class", class_name}, {"class_id", class_id},
            {"class_identity_verified", !class_id.empty()}, {"result", rc}}));
        send_event(event.dump(-1, ' ', false, json::error_handler_t::replace));
    } catch (...) {}
    g_in_jni_observer = false;
    return rc;
}

static json install_jni_observer(JNIEnv* env, const std::string& id) {
    json result = {{"id", id}, {"kind", "jni"}, {"status", "failed"},
        {"observer_version", 2}, {"class_identity", "bounded_weak_reference"},
        {"class_capacity", 1024}, {"coverage", "future_registration_lifecycle_on_current_JNI_table"}, {"live_unhook", false}};
    if (g_register_original || g_unregister_original) {
        result["error"] = "only one JNI observer is supported per process";
        return result;
    }
    if (env->ExceptionCheck()) {
        result["error"] = "VM has a pending exception"; return result;
    }
    jclass cls = env->FindClass("java/lang/Class");
    if (cls) g_class_name = env->GetMethodID(cls, "getName", "()Ljava/lang/String;");
    if (cls) env->DeleteLocalRef(cls);
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (!g_class_name) { result["error"] = "Class.getName unavailable"; return result; }
    g_jni_hook_id = id;
    timespec ts{}; clock_gettime(CLOCK_MONOTONIC, &ts);
    g_jni_instance = std::to_string(getpid()) + "-" + std::to_string(ts.tv_sec) + "-" + std::to_string(ts.tv_nsec);
    void* address = reinterpret_cast<void*>(env->functions->RegisterNatives);
    bool installed = false;
#if defined(__aarch64__)
    installed = sh_hook_sym_addr(address, reinterpret_cast<void*>(observe_register_natives),
        reinterpret_cast<void**>(&g_register_original)) != nullptr;
    if (!installed) result["engine_error"] = sh_get_errno ? sh_get_errno() : -1;
#elif defined(__x86_64__)
    int rc = db_hook(address, reinterpret_cast<void*>(observe_register_natives),
        reinterpret_cast<void**>(&g_register_original));
    installed = rc == 0;
    if (!installed) result["engine_error"] = rc;
#endif
    result["register_natives"] = installed ? "installed" : "failed";
    address = reinterpret_cast<void*>(env->functions->UnregisterNatives);
    bool unregister_installed = false;
#if defined(__aarch64__)
    unregister_installed = sh_hook_sym_addr(address, reinterpret_cast<void*>(observe_unregister_natives),
        reinterpret_cast<void**>(&g_unregister_original)) != nullptr;
    if (!unregister_installed) result["unregister_engine_error"] = sh_get_errno ? sh_get_errno() : -1;
#elif defined(__x86_64__)
    int unregister_rc = db_hook(address, reinterpret_cast<void*>(observe_unregister_natives),
        reinterpret_cast<void**>(&g_unregister_original));
    unregister_installed = unregister_rc == 0;
    if (!unregister_installed) result["unregister_engine_error"] = unregister_rc;
#endif
    result["unregister_natives"] = unregister_installed ? "installed" : "failed";
    result["status"] = installed && unregister_installed ? "installed" : installed || unregister_installed ? "partial" : "failed";
    result["process_instance"] = g_jni_instance;
    return result;
}

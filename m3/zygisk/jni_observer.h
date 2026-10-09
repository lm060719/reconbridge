// Included after the transport/engine helpers in module.cpp.
// Observes future registrations only; never changes arguments, return values or exceptions.
static jint (*g_register_original)(JNIEnv*, jclass, const JNINativeMethod*, jint) = nullptr;
static jmethodID g_class_name = nullptr;
static std::string g_jni_hook_id;
static std::string g_jni_instance;
static thread_local bool g_in_jni_observer = false;

static std::string pointer_hex(uintptr_t value) {
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "0x%llx", (unsigned long long)value);
    return buffer;
}

static jint observe_register_natives(JNIEnv* env, jclass clazz,
                                    const JNINativeMethod* methods, jint count) {
    // Call the real VM first. Failed registrations are not evidence of a binding.
    const jint rc = g_register_original(env, clazz, methods, count);
    if (rc != JNI_OK || g_in_jni_observer || env->ExceptionCheck()) return rc;
    g_in_jni_observer = true;
    try {
        std::string class_name;
        auto name = static_cast<jstring>(env->CallObjectMethod(clazz, g_class_name));
        if (env->ExceptionCheck()) {
            env->ExceptionClear(); // Only our GetName exception; VM exceptions returned above untouched.
        } else if (name) {
            const char* value = env->GetStringUTFChars(name, nullptr);
            if (value) {
                class_name = value;
                env->ReleaseStringUTFChars(name, value);
            }
            if (env->ExceptionCheck()) env->ExceptionClear();
        }
        if (name) env->DeleteLocalRef(name);
        const int captured = std::min(std::max(int(count), 0), 1024);
        for (int i = 0; i < captured; ++i) {
            JNINativeMethod method{};
            if (!safe_read(methods + i, &method, sizeof(method))) break;
            Dl_info info{};
            const bool resolved = dladdr(method.fnPtr, &info) != 0 && info.dli_fbase;
            timespec ts{}; clock_gettime(CLOCK_REALTIME, &ts);
            json event = {{"type", "jni_registration"}, {"source", "RegisterNatives"},
                {"hook_id", g_jni_hook_id}, {"package", g_package},
                {"pid", getpid()}, {"tid", syscall(__NR_gettid)},
                {"process_instance", g_jni_instance},
                {"ts", int64_t(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000},
                {"class", class_name}, {"method", read_cstr(method.name, 1024)},
                {"signature", read_cstr(method.signature, 4096)},
                {"address", pointer_hex(reinterpret_cast<uintptr_t>(method.fnPtr))},
                {"module", resolved && info.dli_fname ? info.dli_fname : ""},
                {"module_base", resolved ? json(pointer_hex(reinterpret_cast<uintptr_t>(info.dli_fbase))) : json(nullptr)},
                {"offset", resolved ? json(pointer_hex(reinterpret_cast<uintptr_t>(method.fnPtr) -
                    reinterpret_cast<uintptr_t>(info.dli_fbase))) : json(nullptr)},
                {"symbol", resolved && info.dli_sname ? info.dli_sname : ""},
                {"registration_count", count}, {"registration_truncated", count > captured},
                {"result", rc}};
            send_event(event.dump(-1, ' ', false, json::error_handler_t::replace));
        }
    } catch (...) {
        // Observation must not unwind through the VM or change the registered binding.
    }
    g_in_jni_observer = false;
    return rc;
}

static json install_jni_observer(JNIEnv* env, const std::string& id) {
    json result = {{"id", id}, {"kind", "jni"}, {"status", "failed"},
        {"coverage", "future_RegisterNatives_on_current_JNI_table"}, {"live_unhook", false}};
    if (g_register_original) {
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
    result["status"] = installed ? "installed" : "failed";
    result["process_instance"] = g_jni_instance;
    return result;
}

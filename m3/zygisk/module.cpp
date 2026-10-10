// ReconBridge M3 —— Zygisk 注入层 + 数据驱动 ShadowHook 执行器。
//
// 运行位置：
//   - Zygisk module（app 域）：zygote fork 目标进程时被 ZygiskNext 注入。
//   - companion（root 域）：读 hook 配置 + libshadowhook.so 字节回传 injected；转发命中事件到 events.log。
//
// 设计：injected 处于 app SELinux 域，不能读 /data/adb、不能直接落盘，故：
//   1) 经 connectCompanion 向 root companion 要 本包的 hook 配置 与 shadowhook.so；
//   2) 用 memfd + android_dlopen_ext 加载 shadowhook（不产生 DT_NEEDED，规避加载期解析）；
//   3) 按配置注入 hook；命中时把事件 JSON 经 companion 转发，companion 追加到 events.log；
//   4) 守护进程 tail events.log 推给 SSE/WS。
//
// 执行器不含任何特定 App 逻辑：只解释 PC 下发的配置。

#include <android/dlext.h>
#include <cstddef>
#include <dlfcn.h>
#include <fcntl.h>
#include <jni.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <unwind.h>
#include <link.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <cerrno>
#include <stdexcept>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "third_party/json.hpp"
#include "native_status.h"
#include "native_live.h"
#include "native_abi.h"
#include "native_lifetime.h"
#include "library_lifetime.h"
#include "native_gateway.h"
#if defined(__aarch64__)
#include "third_party/shadowhook.h"
#elif defined(__x86_64__)
#include "third_party/dobby.h"
#endif
#include "third_party/zygisk.hpp"

using json = nlohmann::json;
using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#define LOG_TAG "ReconBridge"
#include <android/log.h>
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static const char* kInjectSock = "reconbridge_inject";  // 守护进程抽象 socket

// 连接守护进程的注入 IPC 抽象 socket（sepolicy 放行 appdomain->ksu connectto）
static int connect_inject_socket() {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = 0;
    strncpy(addr.sun_path + 1, kInjectSock, sizeof(addr.sun_path) - 2);
    socklen_t len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(kInjectSock);
    if (connect(fd, (struct sockaddr*)&addr, len) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

// ---------------------------------------------------------------------------
// Hook 引擎函数指针（运行时 dlsym，避免 DT_NEEDED）。
// arm64 用 shadowhook；shadowhook 官方不支持 x86_64，x86_64 换 Dobby
//（github.com/jmpews/Dobby，见 m3/dobby-android-build-fix.patch 记录的
// 交叉编译踩坑 + m3/prebuilt/libdobby_x86_64.so）。Dobby 没有 shadowhook
// 的 "lib 未加载先占位、dlopen 后自动补挂" 能力，用下方轮询线程模拟。
// ---------------------------------------------------------------------------
#if defined(__aarch64__)
static int (*sh_init)(int, bool) = nullptr;
static void* (*sh_hook_sym_name)(const char*, const char*, void*, void**) = nullptr;
static void* (*sh_hook_sym_addr)(void*, void*, void**) = nullptr;
static decltype(&shadowhook_hook_sym_name_callback) sh_hook_sym_callback = nullptr;
static int (*sh_get_errno)(void) = nullptr;
static const char* (*sh_to_errmsg)(int) = nullptr;
static int (*sh_reg_dl_init)(shadowhook_dl_info_t, shadowhook_dl_info_t, void*) = nullptr;
static decltype(&shadowhook_register_dl_fini_callback) sh_reg_dl_fini = nullptr;
static decltype(&shadowhook_unhook) sh_unhook = nullptr;
static decltype(&shadowhook_dlopen) sh_open = nullptr;
static decltype(&shadowhook_dlclose) sh_close = nullptr;
static decltype(&shadowhook_dlsym) sh_symbol = nullptr;

static bool resolve_shadowhook(void* h) {
    sh_init = (decltype(sh_init))dlsym(h, "shadowhook_init");
    sh_hook_sym_name = (decltype(sh_hook_sym_name))dlsym(h, "shadowhook_hook_sym_name");
    sh_hook_sym_addr = (decltype(sh_hook_sym_addr))dlsym(h, "shadowhook_hook_sym_addr");
    sh_hook_sym_callback = (decltype(sh_hook_sym_callback))dlsym(h, "shadowhook_hook_sym_name_callback");
    sh_get_errno = (decltype(sh_get_errno))dlsym(h, "shadowhook_get_errno");
    sh_to_errmsg = (decltype(sh_to_errmsg))dlsym(h, "shadowhook_to_errmsg");
    sh_reg_dl_init = (decltype(sh_reg_dl_init))dlsym(h, "shadowhook_register_dl_init_callback");
    sh_reg_dl_fini = (decltype(sh_reg_dl_fini))dlsym(h, "shadowhook_register_dl_fini_callback");
    sh_unhook = (decltype(sh_unhook))dlsym(h, "shadowhook_unhook");
    sh_open = (decltype(sh_open))dlsym(h, "shadowhook_dlopen");
    sh_close = (decltype(sh_close))dlsym(h, "shadowhook_dlclose");
    sh_symbol = (decltype(sh_symbol))dlsym(h, "shadowhook_dlsym");
    return sh_init && sh_hook_sym_name && sh_hook_sym_addr && sh_get_errno;
}

#elif defined(__x86_64__)
static int (*db_hook)(void*, void*, void**) = nullptr;           // DobbyHook(addr, fake, &orig) -> 0=ok
static int (*db_destroy)(void*) = nullptr;
static void* (*db_resolve)(const char*, const char*) = nullptr;  // DobbySymbolResolver(lib, sym) -> addr|null

static bool resolve_dobby(void* h) {
    db_hook = (decltype(db_hook))dlsym(h, "DobbyHook");
    db_destroy = (decltype(db_destroy))dlsym(h, "DobbyDestroy");
    db_resolve = (decltype(db_resolve))dlsym(h, "DobbySymbolResolver");
    return db_hook && db_resolve;
}
#endif

// ---------------------------------------------------------------------------
// 配置结构
// ---------------------------------------------------------------------------
struct Target : NativeSpec {
    void* orig = nullptr;
    void* stub = nullptr;
    size_t status_key = 0;
    std::atomic<int> poll_attempts{0};
    size_t slot = 0;
    uint64_t generation = 0, library_generation = 0;
    uintptr_t address = 0;
    std::string module_key;
    void* gateway = nullptr;
    NativeLifetime lifetime;
    std::atomic<bool> module_valid{true};
    bool quarantined = false;
    bool rearm_pending = false;
    bool unhook_failed = false;
    bool removal_requested = false;
};

static const int MAX_HOOKS = 64;
static std::array<std::shared_ptr<Target>, MAX_HOOKS> g_slots;
static std::vector<std::shared_ptr<Target>> g_ingress_guards;
static std::recursive_mutex g_lifecycle_mutex;
static NativeLibraries g_libraries;
static json g_loader_status = {{"status", "starting"}, {"continuous", false}};
static std::atomic<uint64_t> g_library_sequence{0};
static std::string g_runtime_instance;
static NativeHookStatus g_native_status;
static NativeLiveRegistry g_live;
static std::atomic<bool> g_control_connected{false};
static json g_initial_jni_config = json::array();
static std::atomic<bool> g_status_ready{false};
static std::mutex g_status_publish_mutex;

static std::string g_package;
static int g_evt_fd = -1;
static std::mutex g_send_mtx;

// ---------------------------------------------------------------------------
// 安全内存读取（读自身进程内存，坏地址返回失败而非崩溃）
// ---------------------------------------------------------------------------
static bool safe_read(const void* addr, void* buf, size_t n) {
    if (!addr || n == 0) return false;
    struct iovec local {
        buf, n
    };
    struct iovec remote {
        const_cast<void*>(addr), n
    };
    ssize_t r = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
    return r == (ssize_t)n;
}

static std::string read_cstr(const void* addr, size_t maxn) {
    std::string out;
    char buf[64];
    const char* p = (const char*)addr;
    while (out.size() < maxn) {
        size_t chunk = std::min(sizeof(buf), maxn - out.size());
        if (!safe_read(p, buf, chunk)) break;
        for (size_t i = 0; i < chunk; i++) {
            if (buf[i] == 0) return out;
            out.push_back(buf[i]);
        }
        p += chunk;
    }
    return out;
}

static std::string to_hex(const unsigned char* p, size_t n) {
    static const char* h = "0123456789abcdef";
    std::string o;
    o.reserve(n * 2);
    for (size_t i = 0; i < n; i++) {
        o.push_back(h[p[i] >> 4]);
        o.push_back(h[p[i] & 0xf]);
    }
    return o;
}

// JSON 字符串转义
static void json_esc(std::string& o, const std::string& s) {
    for (char c : s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if ((unsigned char)c < 0x20) {
                    char b[8];
                    snprintf(b, sizeof(b), "\\u%04x", (unsigned char)c);
                    o += b;
                } else {
                    o.push_back(c);
                }
        }
    }
}

// ---------------------------------------------------------------------------
// 调用栈回溯
// ---------------------------------------------------------------------------
struct BtCtx {
    std::vector<uintptr_t> pcs;
    int max;
};
static _Unwind_Reason_Code bt_cb(struct _Unwind_Context* ctx, void* arg) {
    BtCtx* b = (BtCtx*)arg;
    uintptr_t pc = _Unwind_GetIP(ctx);
    if (pc) b->pcs.push_back(pc);
    if ((int)b->pcs.size() >= b->max) return _URC_END_OF_STACK;
    return _URC_NO_REASON;
}

// ---------------------------------------------------------------------------
// companion 事件发送
// ---------------------------------------------------------------------------
static bool write_full(int fd, const void* buf, size_t n) {
    const char* p = (const char*)buf;
    size_t left = n;
    while (left) {
        ssize_t w = send(fd, p, left, MSG_NOSIGNAL);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return false;
        p += w;
        left -= w;
    }
    return true;
}
static bool read_full(int fd, void* buf, size_t n) {
    char* p = (char*)buf;
    size_t left = n;
    while (left) {
        ssize_t r = read(fd, p, left);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return false;
        p += r;
        left -= r;
    }
    return true;
}

// 带类型的分帧发送：[type:1][len:4][payload]。'E'=事件JSON，'D'=内存 dump。
static void send_framed(char type, const void* data, uint32_t len) {
    std::lock_guard<std::mutex> lk(g_send_mtx);
    if (g_evt_fd < 0) return;
    if (!write_full(g_evt_fd, &type, 1) || !write_full(g_evt_fd, &len, 4) ||
        (len && !write_full(g_evt_fd, data, len))) {
        shutdown(g_evt_fd, SHUT_RDWR);  // Wake control reader; it owns close.
        g_evt_fd = -1;
    }
}
static void send_event(const std::string& line) {
    send_framed('E', line.data(), (uint32_t)line.size());
}
// Serialize snapshot creation and delivery so an older snapshot cannot arrive last.
static void publish_native_status() {
    if (!g_status_ready.load()) return;
    std::lock_guard<std::mutex> lock(g_status_publish_mutex);
    std::unique_lock<std::recursive_mutex> lifecycle(g_lifecycle_mutex);
    json status = g_native_status.snapshot();
    auto plan = g_live.snapshot();
    json active = json::array(), retained = json::array();
    for (const auto& item : status["hooks"]) {
        auto row = item;
        const size_t slot = row.value("slot", size_t(MAX_HOOKS));
        if (slot >= MAX_HOOKS) continue;
        const auto& spec = plan->active[slot];
        const bool current = spec && row.value("generation", uint64_t(0)) == plan->generations[slot];
        row["active"] = current;
        if (current) {
            row["id"] = spec->id; row["config_index"] = spec->config_index;
            row["requested"] = spec->requested;
            active.push_back(std::move(row));
        } else retained.push_back(std::move(row));
    }
    const size_t history = retained.size();
    if (history > 128) retained.erase(retained.begin(), retained.begin() + (history - 128));
    status["hooks"] = std::move(active);
    status["retained_hooks"] = std::move(retained);
    status["history_truncated"] = history > 128;
    status["native_status_version"] = 3;
    status["native_float_abi"] = {{"version", 1}, {"types", {"float", "double"}}, {"max_args", 8}, {"explicit_signature", true}};
    status["config_revision"] = plan->revision;
    status["live_reconcile"] = g_control_connected.load();
    status["live_disable"] = g_control_connected.load();
#if defined(__aarch64__)
    status["physical_unhook"] = sh_unhook != nullptr;
#else
    status["physical_unhook"] = db_destroy != nullptr;
#endif
    status["live_unhook"] = status["physical_unhook"] == true && g_control_connected.load();
    status["removal_mode"] = "physical_after_drain";
    status["installation_scope"] = "process_lifetime";
    status["slot_capacity"] = MAX_HOOKS;
    size_t used = 0; for (const auto& target : g_slots) if (target) ++used;
    status["slots_used"] = used;
    status["ingress_guards"] = g_ingress_guards.size();
    status["ingress_guard_capacity"] = 4096;
    status["loader"] = g_loader_status;
    status["loader"]["loaded_images"] = g_libraries.loaded().size();
    status["loader"]["latest_seq"] = g_library_sequence.load();
    status["unload_tracking"] = g_loader_status.value("continuous", false);
    status["process_instance"] = g_runtime_instance;
    status["process"] = g_package;
    status["pid"] = getpid();
    lifecycle.unlock();
    const auto payload = status.dump();
    static std::string previous;
    if (payload == previous) return;
    previous = payload;
    send_framed('S', payload.data(), static_cast<uint32_t>(payload.size()));
}

static void engine_failure(const std::string& engine, const std::string& message, int code = -1) {
    g_native_status.engine({{"name", engine}, {"status", "failed"}, {"error", message}, {"code", code}});
    g_native_status.configuration({{"status", "not_applied"}, {"reason", "engine_unavailable"}});
    g_status_ready = true;
    // Keep IPC open until process exit: daemon only retains connected runtimes.
    publish_native_status();
}

// dump payload = [namelen:2][name][data]
static void send_dump(const std::string& name, const std::string& data) {
    std::string p;
    uint16_t nl = (uint16_t)name.size();
    p.append((const char*)&nl, 2);
    p += name;
    p += data;
    send_framed('D', p.data(), (uint32_t)p.size());
}

// ---------------------------------------------------------------------------
// 命中处理：构造事件 JSON
// ---------------------------------------------------------------------------
static void build_and_send(const NativeSpec& t, uint64_t revision, const long a[8], long ret) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    long long ms = (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;

    std::string o = "{";
    o += "\"ts\":" + std::to_string(ms);
    o += ",\"native_config_revision\":" + std::to_string(revision);
    o += ",\"package\":\"";
    json_esc(o, g_package);
    o += "\",\"hook_id\":\"";
    json_esc(o, t.id);
    o += "\",\"pid\":" + std::to_string(getpid());
    o += ",\"tid\":" + std::to_string((long)syscall(__NR_gettid));
    o += ",\"lib\":\"";
    json_esc(o, t.lib);
    o += "\",\"symbol\":\"";
    json_esc(o, t.symbol);
    o += "\",\"action\":\"";
    o += (t.action == ACT_OBSERVE ? "observe" : t.action == ACT_REPLACE_RET ? "replace_ret" : "replace_arg");
    o += "\"";

    // 参数
    o += ",\"args\":[";
    for (size_t k = 0; k < t.args.size(); k++) {
        const ArgSpec& s = t.args[k];
        if (k) o += ",";
        if (native_floating(s.type)) {
            auto capture = native_float_capture(s.type, static_cast<uint64_t>(a[s.index]));
            capture["index"] = s.index;
            o += capture.dump();
            continue;
        }
        o += "{\"index\":" + std::to_string(s.index) + ",\"type\":\"";
        long v = (s.index >= 0 && s.index < 8) ? a[s.index] : 0;
        switch (s.type) {
            case T_FLOAT: case T_DOUBLE: case T_VOID: break;  // validated/captured above
            case T_INT:
                o += "int\",\"value\":" + std::to_string(v);
                break;
            case T_PTR: {
                char b[24];
                snprintf(b, sizeof(b), "0x%llx", (unsigned long long)v);
                o += "ptr\",\"value\":\"";
                o += b;
                o += "\"";
                break;
            }
            case T_STR: {
                std::string sv = read_cstr((const void*)v, s.max > 0 ? s.max : 256);
                o += "string\",\"value\":\"";
                json_esc(o, sv);
                o += "\"";
                break;
            }
            case T_BYTES: {
                int len = s.len;
                if (s.len_from >= 0 && s.len_from < 8) len = (int)a[s.len_from];
                if (len < 0) len = 0;
                if (len > 4096) len = 4096;  // 上限保护
                std::string hex;
                if (len > 0) {
                    std::vector<unsigned char> tmp(len);
                    if (safe_read((const void*)v, tmp.data(), len))
                        hex = to_hex(tmp.data(), len);
                }
                o += "bytes\",\"len\":" + std::to_string(len) + ",\"value\":\"" + hex + "\"";
                break;
            }
        }
        o += "}";
    }
    o += "]";

    // 返回值
    if (t.cap_ret && native_floating(t.ret_type)) {
        o += ",\"ret\":" + native_float_capture(t.ret_type, static_cast<uint64_t>(ret)).dump();
    } else if (t.cap_ret) {
        o += ",\"ret\":{\"type\":\"";
        switch (t.ret_type) {
            case T_PTR: {
                char b[24];
                snprintf(b, sizeof(b), "0x%llx", (unsigned long long)ret);
                o += "ptr\",\"value\":\"";
                o += b;
                o += "\"";
                break;
            }
            case T_STR: {
                std::string sv = read_cstr((const void*)ret, 256);
                o += "string\",\"value\":\"";
                json_esc(o, sv);
                o += "\"";
                break;
            }
            default:
                o += "int\",\"value\":" + std::to_string(ret);
        }
        o += "}";
    }

    // 调用栈
    if (t.backtrace) {
        BtCtx b;
        b.max = 16;
        _Unwind_Backtrace(bt_cb, &b);
        o += ",\"backtrace\":[";
        for (size_t k = 0; k < b.pcs.size(); k++) {
            if (k) o += ",";
            char hb[24];
            snprintf(hb, sizeof(hb), "\"0x%llx\"", (unsigned long long)b.pcs[k]);
            o += hb;
        }
        o += "]";
    }

    // 内存 dump（如加固壳解密后的 dex）：读 [base, base+size) 回传落盘
    if (t.has_dump && t.dump_base_arg >= 0 && t.dump_base_arg < 8) {
        long base = a[t.dump_base_arg];
        long size = 0;
        if (t.dump_size_fixed >= 0) size = t.dump_size_fixed;
        else if (t.dump_size_arg >= 0 && t.dump_size_arg < 8) size = a[t.dump_size_arg];
        if (size > 0 && size <= t.dump_max && base) {
            std::vector<char> data(size);
            if (safe_read((const void*)base, data.data(), size)) {
                struct timespec ts2;
                clock_gettime(CLOCK_REALTIME, &ts2);
                long long ms2 = (long long)ts2.tv_sec * 1000 + ts2.tv_nsec / 1000000;
                std::string name = g_package + "_" + t.id + "_" + std::to_string(ms2) + "." + t.dump_ext;
                send_dump(name, std::string(data.data(), size));
                o += ",\"dump\":{\"saved\":\"";
                json_esc(o, name);
                o += "\",\"bytes\":" + std::to_string(size) + "}";
            }
        }
    }

    o += "}";
    send_event(o);
}

// ---------------------------------------------------------------------------
// 代理池：每个 hook 点一个独立 proxy_i，转发到 proxy_common(i, x0..x7)
// ---------------------------------------------------------------------------
extern "C" __attribute__((visibility("hidden"))) void rb_native_dispatch(uintptr_t context, NativeFrame* frame) {
    auto& target = *reinterpret_cast<Target*>(context);
    // A thread delayed before entering the gateway may arrive after unhook.
    // Never call the freed engine trampoline or another slot owner's signature.
    invoke_native_generation(g_live, target, *frame,
        [](const NativeSpec& spec, uint64_t revision, const std::array<long, 8>& args, long result) {
            build_and_send(spec, revision, args.data(), result);
        });
}

#include "native_runtime.h"

// ---------------------------------------------------------------------------
// 解析配置并注入
// ---------------------------------------------------------------------------
#include "jni_observer.h"

static void apply_hooks_locked(const std::string& cfg_text, JNIEnv* env = nullptr) {
    try {
        const json cfg = json::parse(cfg_text);
        auto change = g_live.reconcile(cfg, prepare_native_target);
        json jni_config = json::array();
        for (const auto& target : cfg["targets"])
            if (target.value("kind", std::string("native")) == "jni") jni_config.push_back(target);
        if (env) {
            g_initial_jni_config = jni_config;
            json observers = json::array();
            for (const auto& target : jni_config) {
                try { observers.push_back(install_jni_observer(env, target.value("id", "__rb_jni"))); }
                catch (const std::exception& error) { observers.push_back({{"status", "failed"}, {"error", error.what()}}); }
            }
            g_native_status.jni(std::move(observers));
        }
        reconcile_native_runtime();
        g_native_status.configuration({{"status", "applied"}, {"config_revision", change.plan->revision},
            {"changed", change.changed}, {"native_targets", change.plan->desired.size()},
            {"jni_restart_required", jni_config != g_initial_jni_config},
            {"semantics", "future_invocations; in-flight calls retain prior config"}});
    } catch (const std::exception& error) {
        g_native_status.configuration({{"status", "failed"}, {"error", error.what()},
            {"retained_previous_config", true}, {"config_revision", g_live.snapshot()->revision}});
    }
    g_status_ready = true;
}

static void apply_hooks(const std::string& text, JNIEnv* env = nullptr) {
    with_loader_lock([&] {
        std::lock_guard<std::recursive_mutex> lock(g_lifecycle_mutex);
        apply_hooks_locked(text, env);
    });
    publish_native_status();
}

static void start_native_control(int fd) {
    g_control_connected = true;
    std::thread([fd]() {
        for (;;) {
            char type;
            uint32_t size;
            if (!read_full(fd, &type, 1) || !read_full(fd, &size, 4) || size > (16u << 20)) break;
            std::string payload(size, 0);
            if (size && !read_full(fd, &payload[0], size)) break;
            if (type == 'R') apply_hooks(payload);
        }
        g_control_connected = false;
        std::lock_guard<std::mutex> lock(g_send_mtx);
        if (g_evt_fd == fd) g_evt_fd = -1;
        close(fd);
    }).detach();
    const std::string hello = R"({"kind":"native","protocol":1,"removal_mode":"physical_after_drain"})";
    send_framed('H', hello.data(), static_cast<uint32_t>(hello.size()));
    start_native_worker();
    publish_native_status();
}

// ---------------------------------------------------------------------------
// Zygisk module
// ---------------------------------------------------------------------------
class ReconModule : public zygisk::ModuleBase {
public:
    void onLoad(Api* api, JNIEnv* env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(AppSpecializeArgs* args) override {
        // 读取进程名（主进程通常 = 包名）
        if (args->nice_name) {
            const char* np = env->GetStringUTFChars(args->nice_name, nullptr);
            if (np) {
                g_package = np;
                env->ReleaseStringUTFChars(args->nice_name, np);
            }
        }
    }

    void postAppSpecialize(const AppSpecializeArgs*) override {
        if (g_package.empty()) {
            unload();
            return;
        }
        int fd = connect_inject_socket();  // 直连守护进程，不走 Zygisk companion
        if (fd < 0) {
            unload();
            return;
        }
        // 发包名
        uint32_t plen = (uint32_t)g_package.size();
        if (!write_full(fd, &plen, 4) || !write_full(fd, g_package.data(), plen)) {
            close(fd);
            unload();
            return;
        }
        uint8_t has = 0;
        if (!read_full(fd, &has, 1) || !has) {
            close(fd);
            unload();
            return;
        }
        // 读配置 + shadowhook.so
        uint32_t clen = 0;
        if (!read_full(fd, &clen, 4) || clen == 0 || clen > (16u << 20)) {
            close(fd);
            unload();
            return;
        }
        std::string cfg(clen, 0);
        if (!read_full(fd, &cfg[0], clen)) {
            close(fd);
            unload();
            return;
        }

        g_evt_fd = fd;
        // 从 /system/lib64 按名加载 hook 引擎（模块把它挂到系统库目录，处于默认命名空间；
        // arm64=shadowhook 需同级 libshadowhook_nothing.so 供其 linker init dlopen；
        // x86_64=Dobby，无此要求，直接 dlopen 即可）。
#if defined(__aarch64__)
        void* h = dlopen("libshadowhook.so", RTLD_NOW);
        if (!h || !resolve_shadowhook(h)) {
            const char* error = dlerror();
            engine_failure("shadowhook", error ? error : "required engine symbol missing");
            return;  // 已尝试连接，保持加载
        }
        int rc = sh_init(SHADOWHOOK_MODE_UNIQUE, false);
        if (rc != 0) {
            engine_failure("shadowhook", sh_to_errmsg ? sh_to_errmsg(rc) : "initialization failed", rc);
            return;
        }
#elif defined(__x86_64__)
        void* h = dlopen("libdobby.so", RTLD_NOW);
        if (!h || !resolve_dobby(h)) {
            const char* error = dlerror();
            engine_failure("dobby", error ? error : "required engine symbol missing");
            return;  // 已尝试连接，保持加载
        }
#endif
#if defined(__aarch64__)
        g_native_status.engine({{"name", "shadowhook"}, {"status", "ready"},
                                {"symbol_resolution", "loader_snapshot_poll"}});
#elif defined(__x86_64__)
        g_native_status.engine({{"name", "dobby"}, {"status", "ready"}});
#endif
        LOGI("为 %s 注入 hook（配置 %u 字节）", g_package.c_str(), clen);
        initialize_native_loader();
        apply_hooks(cfg, env);
        start_native_control(fd);
        // 有 hook：不 unload，保持代理常驻
    }

private:
    Api* api = nullptr;
    JNIEnv* env = nullptr;

    void unload() {
        // 无 hook：卸载本模块，省内存、更隐蔽
        if (api) api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }
};

// 注：不再使用 Zygisk companion —— 注入层通过 connect_inject_socket() 直连守护进程
// （root/ksu 域）取配置/回传事件，链路更简单、避开 ZN companion 的权限限制。

REGISTER_ZYGISK_MODULE(ReconModule)

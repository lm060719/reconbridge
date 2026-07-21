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
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "third_party/json.hpp"
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
static int (*sh_get_errno)(void) = nullptr;
static const char* (*sh_to_errmsg)(int) = nullptr;
static int (*sh_reg_dl_init)(shadowhook_dl_info_t, shadowhook_dl_info_t, void*) = nullptr;

static bool resolve_shadowhook(void* h) {
    sh_init = (decltype(sh_init))dlsym(h, "shadowhook_init");
    sh_hook_sym_name = (decltype(sh_hook_sym_name))dlsym(h, "shadowhook_hook_sym_name");
    sh_hook_sym_addr = (decltype(sh_hook_sym_addr))dlsym(h, "shadowhook_hook_sym_addr");
    sh_get_errno = (decltype(sh_get_errno))dlsym(h, "shadowhook_get_errno");
    sh_to_errmsg = (decltype(sh_to_errmsg))dlsym(h, "shadowhook_to_errmsg");
    sh_reg_dl_init = (decltype(sh_reg_dl_init))dlsym(h, "shadowhook_register_dl_init_callback");
    return sh_init && sh_hook_sym_name && sh_hook_sym_addr;
}

#elif defined(__x86_64__)
static int (*db_hook)(void*, void*, void**) = nullptr;           // DobbyHook(addr, fake, &orig) -> 0=ok
static void* (*db_resolve)(const char*, const char*) = nullptr;  // DobbySymbolResolver(lib, sym) -> addr|null

static bool resolve_dobby(void* h) {
    db_hook = (decltype(db_hook))dlsym(h, "DobbyHook");
    db_resolve = (decltype(db_resolve))dlsym(h, "DobbySymbolResolver");
    return db_hook && db_resolve;
}
#endif

// ---------------------------------------------------------------------------
// 配置结构
// ---------------------------------------------------------------------------
enum ArgType { T_INT, T_PTR, T_STR, T_BYTES };
enum ActionType { ACT_OBSERVE, ACT_REPLACE_RET, ACT_REPLACE_ARG };

struct ArgSpec {
    int index = 0;
    ArgType type = T_INT;
    int len = -1;       // bytes 固定长度
    int len_from = -1;  // bytes 长度取自第 N 个参数
    int max = 256;      // string 最长
};

struct Target {
    std::string id, lib, symbol;
    bool has_offset = false;
    uint64_t offset = 0;
    std::vector<ArgSpec> args;
    bool cap_ret = false;
    ArgType ret_type = T_INT;
    bool backtrace = false;
    // dump：命中时把 [x_base_arg, +x_size_arg) 内存回传落盘（用于内存 dex dump 等）
    bool has_dump = false;
    int dump_base_arg = -1;
    int dump_size_arg = -1;
    long dump_size_fixed = -1;  // 固定长度（与 size_arg 二选一）
    int dump_max = 32 * 1024 * 1024;  // 单次上限 32MB
    std::string dump_ext = "bin";
    ActionType action = ACT_OBSERVE;
    long ret_value = 0;
    std::vector<std::pair<int, long>> arg_overrides;
    // 运行时
    void* orig = nullptr;
    void* stub = nullptr;
    bool applied = false;
};

static const int MAX_HOOKS = 64;
static Target g_slots[MAX_HOOKS];
static int g_nslots = 0;

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
        ssize_t w = write(fd, p, left);
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
        g_evt_fd = -1;  // 断开则不再发
    }
}
static void send_event(const std::string& line) {
    send_framed('E', line.data(), (uint32_t)line.size());
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
static void build_and_send(int idx, const long a[8], long ret) {
    Target& t = g_slots[idx];
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    long long ms = (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;

    std::string o = "{";
    o += "\"ts\":" + std::to_string(ms);
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
        o += "{\"index\":" + std::to_string(s.index) + ",\"type\":\"";
        long v = (s.index >= 0 && s.index < 8) ? a[s.index] : 0;
        switch (s.type) {
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
    if (t.cap_ret) {
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
typedef long (*fn8)(long, long, long, long, long, long, long, long);

static long proxy_common(int idx, long a0, long a1, long a2, long a3, long a4, long a5, long a6, long a7) {
    Target& t = g_slots[idx];
    long a[8] = {a0, a1, a2, a3, a4, a5, a6, a7};
    if (t.action == ACT_REPLACE_ARG)
        for (auto& ov : t.arg_overrides)
            if (ov.first >= 0 && ov.first < 8) a[ov.first] = ov.second;

    long ret = 0;
    if (t.orig)
        ret = ((fn8)t.orig)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);

    build_and_send(idx, a, ret);

    if (t.action == ACT_REPLACE_RET) return t.ret_value;
    return ret;
}

#define PROXY(i)                                                                                    \
    static long proxy_##i(long a0, long a1, long a2, long a3, long a4, long a5, long a6, long a7) { \
        return proxy_common(i, a0, a1, a2, a3, a4, a5, a6, a7);                                     \
    }
// 生成 64 个
PROXY(0) PROXY(1) PROXY(2) PROXY(3) PROXY(4) PROXY(5) PROXY(6) PROXY(7)
PROXY(8) PROXY(9) PROXY(10) PROXY(11) PROXY(12) PROXY(13) PROXY(14) PROXY(15)
PROXY(16) PROXY(17) PROXY(18) PROXY(19) PROXY(20) PROXY(21) PROXY(22) PROXY(23)
PROXY(24) PROXY(25) PROXY(26) PROXY(27) PROXY(28) PROXY(29) PROXY(30) PROXY(31)
PROXY(32) PROXY(33) PROXY(34) PROXY(35) PROXY(36) PROXY(37) PROXY(38) PROXY(39)
PROXY(40) PROXY(41) PROXY(42) PROXY(43) PROXY(44) PROXY(45) PROXY(46) PROXY(47)
PROXY(48) PROXY(49) PROXY(50) PROXY(51) PROXY(52) PROXY(53) PROXY(54) PROXY(55)
PROXY(56) PROXY(57) PROXY(58) PROXY(59) PROXY(60) PROXY(61) PROXY(62) PROXY(63)

#define PROXY_REF(i) (void*)proxy_##i
static void* g_proxy[MAX_HOOKS] = {
    PROXY_REF(0), PROXY_REF(1), PROXY_REF(2), PROXY_REF(3), PROXY_REF(4), PROXY_REF(5), PROXY_REF(6), PROXY_REF(7),
    PROXY_REF(8), PROXY_REF(9), PROXY_REF(10), PROXY_REF(11), PROXY_REF(12), PROXY_REF(13), PROXY_REF(14), PROXY_REF(15),
    PROXY_REF(16), PROXY_REF(17), PROXY_REF(18), PROXY_REF(19), PROXY_REF(20), PROXY_REF(21), PROXY_REF(22), PROXY_REF(23),
    PROXY_REF(24), PROXY_REF(25), PROXY_REF(26), PROXY_REF(27), PROXY_REF(28), PROXY_REF(29), PROXY_REF(30), PROXY_REF(31),
    PROXY_REF(32), PROXY_REF(33), PROXY_REF(34), PROXY_REF(35), PROXY_REF(36), PROXY_REF(37), PROXY_REF(38), PROXY_REF(39),
    PROXY_REF(40), PROXY_REF(41), PROXY_REF(42), PROXY_REF(43), PROXY_REF(44), PROXY_REF(45), PROXY_REF(46), PROXY_REF(47),
    PROXY_REF(48), PROXY_REF(49), PROXY_REF(50), PROXY_REF(51), PROXY_REF(52), PROXY_REF(53), PROXY_REF(54), PROXY_REF(55),
    PROXY_REF(56), PROXY_REF(57), PROXY_REF(58), PROXY_REF(59), PROXY_REF(60), PROXY_REF(61), PROXY_REF(62), PROXY_REF(63),
};

// ---------------------------------------------------------------------------
// 加载 shadowhook（memfd + android_dlopen_ext，无 DT_NEEDED）
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// offset 模式：找 lib 的加载基址 / 延迟到 dlopen 后再挂
// ---------------------------------------------------------------------------
static std::string base_name(const std::string& p) {
    size_t s = p.find_last_of('/');
    return s == std::string::npos ? p : p.substr(s + 1);
}

struct BaseFind {
    std::string lib;
    uintptr_t base;
};
static int base_iter_cb(struct dl_phdr_info* info, size_t, void* data) {
    BaseFind* bf = (BaseFind*)data;
    if (info->dlpi_name && base_name(info->dlpi_name) == bf->lib) {
        bf->base = (uintptr_t)info->dlpi_addr;
        return 1;
    }
    return 0;
}
static uintptr_t find_lib_base(const std::string& lib) {
    BaseFind bf{lib, 0};
    dl_iterate_phdr(base_iter_cb, &bf);
    return bf.base;
}

static void apply_offset_hook(int idx, uintptr_t base) {
    Target& t = g_slots[idx];
    if (t.applied) return;
    void* addr = (void*)(base + t.offset);
#if defined(__aarch64__)
    t.stub = sh_hook_sym_addr(addr, g_proxy[idx], &t.orig);
    if (t.stub) {
        t.applied = true;
        LOGI("offset hook applied: %s+0x%llx @%p", t.lib.c_str(), (unsigned long long)t.offset, addr);
    } else {
        int e = sh_get_errno ? sh_get_errno() : -1;
        LOGE("offset hook fail %s+0x%llx: %s", t.lib.c_str(), (unsigned long long)t.offset,
             sh_to_errmsg ? sh_to_errmsg(e) : "?");
    }
#elif defined(__x86_64__)
    int rc = db_hook ? db_hook(addr, g_proxy[idx], &t.orig) : -1;
    if (rc == 0) {
        t.stub = addr;
        t.applied = true;
        LOGI("offset hook applied: %s+0x%llx @%p", t.lib.c_str(), (unsigned long long)t.offset, addr);
    } else {
        LOGE("offset hook fail %s+0x%llx: DobbyHook rc=%d", t.lib.c_str(), (unsigned long long)t.offset, rc);
    }
#endif
}

// dlopen 后回调：为尚未挂上的 offset hook 补挂
#if defined(__aarch64__)
static bool g_dl_cb_registered = false;
#endif
static void on_dl_post(struct dl_phdr_info* info, size_t, void*) {
    if (!info->dlpi_name) return;
    std::string bn = base_name(info->dlpi_name);
    for (int i = 0; i < g_nslots; i++) {
        Target& t = g_slots[i];
        if (t.has_offset && !t.applied && t.lib == bn)
            apply_offset_hook(i, (uintptr_t)info->dlpi_addr);
    }
}

#if defined(__x86_64__)
// ---------------------------------------------------------------------------
// Dobby 版 pending 补挂：symbol 型重试 DobbySymbolResolver，offset 型复用
// on_dl_post（签名与 dl_iterate_phdr 回调一致，直接手动全量重扫触发）。
// 每 150ms 一轮，30s 后放弃——目标 lib 多数在 App 启动早期就已加载，
// 实测（arm64/shadowhook 路径）命中通常在第 1-2 轮内完成。
// ---------------------------------------------------------------------------
// dl_iterate_phdr 要求回调返回 int，on_dl_post 因 shadowhook_dl_info_t 签名要求是
// void 返回值（arm64 分支用它注册回调），这里包一层薄 trampoline 适配。
static int dl_iter_trampoline(struct dl_phdr_info* info, size_t size, void* data) {
    on_dl_post(info, size, data);
    return 0;
}

static void apply_symbol_hook(int idx) {
    Target& t = g_slots[idx];
    if (t.applied) return;
    void* addr = db_resolve ? db_resolve(t.lib.c_str(), t.symbol.c_str()) : nullptr;
    if (!addr) return;
    int rc = db_hook ? db_hook(addr, g_proxy[idx], &t.orig) : -1;
    if (rc == 0) {
        t.stub = addr;
        t.applied = true;
        LOGI("sym hook %s!%s -> applied", t.lib.c_str(), t.symbol.c_str());
    } else {
        LOGE("sym hook %s!%s fail: DobbyHook rc=%d", t.lib.c_str(), t.symbol.c_str(), rc);
    }
}

static std::vector<int> g_pending_sym_idx;
static std::vector<int> g_pending_offset_idx;
static std::mutex g_pending_mtx;
static std::atomic<bool> g_poll_running{false};

static void start_pending_poll() {
    bool expected = false;
    if (!g_poll_running.compare_exchange_strong(expected, true)) return;  // 只起一次
    std::thread([]() {
        for (int tick = 0; tick < 200; tick++) {
            usleep(150 * 1000);
            std::vector<int> sym_todo, off_todo;
            {
                std::lock_guard<std::mutex> lk(g_pending_mtx);
                sym_todo = g_pending_sym_idx;
                off_todo = g_pending_offset_idx;
            }
            if (sym_todo.empty() && off_todo.empty()) return;
            for (int idx : sym_todo) apply_symbol_hook(idx);
            if (!off_todo.empty()) dl_iterate_phdr(dl_iter_trampoline, nullptr);
            std::lock_guard<std::mutex> lk(g_pending_mtx);
            g_pending_sym_idx.erase(std::remove_if(g_pending_sym_idx.begin(), g_pending_sym_idx.end(),
                                                    [](int i) { return g_slots[i].applied; }),
                                     g_pending_sym_idx.end());
            g_pending_offset_idx.erase(std::remove_if(g_pending_offset_idx.begin(), g_pending_offset_idx.end(),
                                                       [](int i) { return g_slots[i].applied; }),
                                        g_pending_offset_idx.end());
        }
    }).detach();
}
#endif

// ---------------------------------------------------------------------------
// 解析配置并注入
// ---------------------------------------------------------------------------
static ArgType parse_type(const std::string& s) {
    if (s == "ptr") return T_PTR;
    if (s == "string") return T_STR;
    if (s == "bytes") return T_BYTES;
    return T_INT;
}

static void apply_hooks(const std::string& cfg_text) {
    json cfg;
    try {
        cfg = json::parse(cfg_text);
    } catch (...) {
        LOGE("hook 配置解析失败");
        return;
    }
    if (!cfg.contains("targets") || !cfg["targets"].is_array()) return;

    for (auto& jt : cfg["targets"]) {
        if (g_nslots >= MAX_HOOKS) {
            LOGE("hook 数超过上限 %d", MAX_HOOKS);
            break;
        }
        int idx = g_nslots;
        Target& t = g_slots[idx];
        t = Target{};
        t.id = jt.value("id", std::string("h") + std::to_string(idx));
        t.lib = jt.value("lib", "");
        if (jt.contains("symbol") && jt["symbol"].is_string()) t.symbol = jt["symbol"].get<std::string>();
        if (jt.contains("offset")) {
            t.has_offset = true;
            if (jt["offset"].is_string()) {
                std::string os = jt["offset"];
                t.offset = strtoull(os.c_str(), nullptr, os.rfind("0x", 0) == 0 ? 16 : 10);
            } else {
                t.offset = jt["offset"].get<uint64_t>();
            }
        }
        // capture
        if (jt.contains("capture")) {
            auto& cap = jt["capture"];
            if (cap.contains("args") && cap["args"].is_array()) {
                for (auto& ja : cap["args"]) {
                    ArgSpec s;
                    s.index = ja.value("index", 0);
                    s.type = parse_type(ja.value("type", std::string("int")));
                    s.len = ja.value("len", -1);
                    s.len_from = ja.value("len_from", -1);
                    s.max = ja.value("max", 256);
                    t.args.push_back(s);
                }
            }
            if (cap.contains("ret")) {
                t.cap_ret = cap["ret"].value("capture", false);
                t.ret_type = parse_type(cap["ret"].value("type", std::string("int")));
            }
            t.backtrace = cap.value("backtrace", false);
            if (cap.contains("dump")) {
                auto& dp = cap["dump"];
                t.has_dump = true;
                t.dump_base_arg = dp.value("base_arg", -1);
                t.dump_size_arg = dp.value("size_arg", -1);
                t.dump_size_fixed = dp.value("size", (long)-1);
                t.dump_max = dp.value("max", 32 * 1024 * 1024);
                t.dump_ext = dp.value("ext", std::string("bin"));
            }
        }
        // action
        if (jt.contains("action")) {
            auto& ac = jt["action"];
            std::string at = ac.value("type", std::string("observe"));
            t.action = (at == "replace_ret") ? ACT_REPLACE_RET : (at == "replace_arg") ? ACT_REPLACE_ARG : ACT_OBSERVE;
            if (ac.contains("ret_value")) t.ret_value = ac["ret_value"].get<long>();
            if (ac.contains("arg_overrides") && ac["arg_overrides"].is_array())
                for (auto& ov : ac["arg_overrides"])
                    t.arg_overrides.push_back({ov.value("index", 0), (long)ov.value("value", 0)});
        }

        g_nslots++;  // 占用该 slot

        // 注入
#if defined(__aarch64__)
        if (!t.symbol.empty()) {
            t.stub = sh_hook_sym_name(t.lib.c_str(), t.symbol.c_str(), g_proxy[idx], &t.orig);
            int e = sh_get_errno ? sh_get_errno() : 0;
            if (t.stub || e == SHADOWHOOK_ERRNO_PENDING) {
                t.applied = (t.stub != nullptr);
                LOGI("sym hook %s!%s -> %s", t.lib.c_str(), t.symbol.c_str(),
                     t.applied ? "applied" : "pending");
            } else {
                LOGE("sym hook %s!%s fail: %s", t.lib.c_str(), t.symbol.c_str(),
                     sh_to_errmsg ? sh_to_errmsg(e) : "?");
            }
        } else if (t.has_offset) {
            uintptr_t base = find_lib_base(t.lib);
            if (base) {
                apply_offset_hook(idx, base);
            } else {
                // lib 尚未加载：注册 dlopen 回调延迟补挂
                if (!g_dl_cb_registered && sh_reg_dl_init) {
                    sh_reg_dl_init(nullptr, on_dl_post, nullptr);
                    g_dl_cb_registered = true;
                }
                LOGI("offset hook %s+0x%llx pending(dlopen)", t.lib.c_str(),
                     (unsigned long long)t.offset);
            }
        }
#elif defined(__x86_64__)
        if (!t.symbol.empty()) {
            apply_symbol_hook(idx);
            if (!t.applied) {
                std::lock_guard<std::mutex> lk(g_pending_mtx);
                g_pending_sym_idx.push_back(idx);
                start_pending_poll();
                LOGI("sym hook %s!%s -> pending(poll)", t.lib.c_str(), t.symbol.c_str());
            }
        } else if (t.has_offset) {
            uintptr_t base = find_lib_base(t.lib);
            if (base) {
                apply_offset_hook(idx, base);
            } else {
                std::lock_guard<std::mutex> lk(g_pending_mtx);
                g_pending_offset_idx.push_back(idx);
                start_pending_poll();
                LOGI("offset hook %s+0x%llx pending(poll)", t.lib.c_str(),
                     (unsigned long long)t.offset);
            }
        }
#endif
    }
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

        // 从 /system/lib64 按名加载 hook 引擎（模块把它挂到系统库目录，处于默认命名空间；
        // arm64=shadowhook 需同级 libshadowhook_nothing.so 供其 linker init dlopen；
        // x86_64=Dobby，无此要求，直接 dlopen 即可）。
#if defined(__aarch64__)
        void* h = dlopen("libshadowhook.so", RTLD_NOW);
        if (!h || !resolve_shadowhook(h)) {
            LOGE("加载 shadowhook 失败: %s", dlerror());
            close(fd);
            return;  // 已尝试连接，保持加载
        }
        int rc = sh_init(SHADOWHOOK_MODE_UNIQUE, false);
        if (rc != 0) {
            LOGE("shadowhook_init 失败 rc=%d (%s)", rc, sh_to_errmsg ? sh_to_errmsg(rc) : "?");
            close(fd);
            return;
        }
#elif defined(__x86_64__)
        void* h = dlopen("libdobby.so", RTLD_NOW);
        if (!h || !resolve_dobby(h)) {
            LOGE("加载 dobby 失败: %s", dlerror());
            close(fd);
            return;  // 已尝试连接，保持加载
        }
#endif
        g_evt_fd = fd;  // 保留用于回传事件
        LOGI("为 %s 注入 hook（配置 %u 字节）", g_package.c_str(), clen);
        apply_hooks(cfg);
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

// M3 动态子系统实现：hook 配置下发 + hook 命中事件推流（SSE + 极简 WS）。
#include "dynamic.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstddef>
#include <dirent.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <fstream>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "third_party/json.hpp"

using json = nlohmann::json;
using namespace httplib;

namespace dynamic {

// ---------------------------------------------------------------------------
// 路径 / 全局状态
// ---------------------------------------------------------------------------
static std::string g_base_dir;
static std::string g_hooks_dir;
static std::string g_events_log;
static std::string g_dumps_dir;

static void log_line(const std::string& s) {
    std::ofstream f(g_base_dir + "/daemon.log", std::ios::app);
    if (f.good()) f << "[dynamic] " << s << "\n";
}

static bool valid_pkg(const std::string& s) {
    if (s.empty() || s.size() > 256) return false;
    for (char c : s)
        if (!(isalnum((unsigned char)c) || c == '.' || c == '_')) return false;
    return true;
}

// 小工具：以 root 执行命令（daemon 本身是 root），用于 am force-stop
static void run_detached(const std::vector<std::string>& argv) {
    pid_t pid = fork();
    if (pid == 0) {
        std::vector<char*> a;
        for (auto& s : argv) a.push_back(const_cast<char*>(s.c_str()));
        a.push_back(nullptr);
        execvp(a[0], a.data());
        _exit(127);
    } else if (pid > 0) {
        int st;
        waitpid(pid, &st, 0);
    }
}

// ---------------------------------------------------------------------------
// 事件广播器：多个 SSE/WS 订阅者，各自一个带超时的阻塞队列
// ---------------------------------------------------------------------------
struct Subscriber {
    std::mutex m;
    std::condition_variable cv;
    std::deque<std::string> q;
    bool alive = true;

    // 超时毫秒内取一条；取到返回 true
    bool pop(std::string& out, int timeout_ms) {
        std::unique_lock<std::mutex> lk(m);
        if (!cv.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                         [&] { return !q.empty() || !alive; }))
            return false;
        if (!q.empty()) {
            out = std::move(q.front());
            q.pop_front();
            return true;
        }
        return false;
    }
    void push(const std::string& line) {
        {
            std::lock_guard<std::mutex> lk(m);
            if (q.size() < 10000) q.push_back(line);  // 防爆
        }
        cv.notify_one();
    }
};

class Broadcaster {
    std::mutex m_;
    std::set<std::shared_ptr<Subscriber>> subs_;

public:
    std::shared_ptr<Subscriber> subscribe() {
        auto s = std::make_shared<Subscriber>();
        std::lock_guard<std::mutex> lk(m_);
        subs_.insert(s);
        return s;
    }
    void unsubscribe(const std::shared_ptr<Subscriber>& s) {
        std::lock_guard<std::mutex> lk(m_);
        subs_.erase(s);
    }
    void broadcast(const std::string& line) {
        std::lock_guard<std::mutex> lk(m_);
        for (auto& s : subs_) s->push(line);
    }
    size_t count() {
        std::lock_guard<std::mutex> lk(m_);
        return subs_.size();
    }
};

static Broadcaster g_broadcaster;

// ---------------------------------------------------------------------------
// events.log 轮询 tail：把 companion 追加的事件行广播出去
// ---------------------------------------------------------------------------
static void events_watcher() {
    off_t offset = 0;
    std::string partial;
    // 起始定位到文件末尾，不回放历史
    {
        struct stat st;
        if (stat(g_events_log.c_str(), &st) == 0) offset = st.st_size;
    }
    while (true) {
        struct stat st;
        if (stat(g_events_log.c_str(), &st) == 0) {
            if (st.st_size < offset) {  // 被截断/重建
                offset = 0;
                partial.clear();
            }
            if (st.st_size > offset) {
                int fd = open(g_events_log.c_str(), O_RDONLY);
                if (fd >= 0) {
                    lseek(fd, offset, SEEK_SET);
                    char buf[8192];
                    ssize_t n;
                    while ((n = read(fd, buf, sizeof(buf))) > 0) {
                        partial.append(buf, n);
                        offset += n;
                        size_t pos;
                        while ((pos = partial.find('\n')) != std::string::npos) {
                            std::string line = partial.substr(0, pos);
                            partial.erase(0, pos + 1);
                            if (!line.empty()) g_broadcaster.broadcast(line);
                        }
                    }
                    close(fd);
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

// ---------------------------------------------------------------------------
// 注入 IPC：抽象 unix socket @reconbridge_inject
// 注入层（app 域）直接连本守护进程（root/ksu 域，需 sepolicy 放行 connectto），
// 取本包 hook 配置 + libshadowhook.so 字节，并把命中事件回传（直接广播给 SSE/WS）。
// 这样不依赖 Zygisk companion，整条链路由守护进程掌控。
// ---------------------------------------------------------------------------
static const char* kInjectSock = "reconbridge_inject";  // 抽象命名空间

static bool sock_write_full(int fd, const void* buf, size_t n) {
    const char* p = (const char*)buf;
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w <= 0) return false;
        p += w;
        n -= w;
    }
    return true;
}
static bool sock_read_full(int fd, void* buf, size_t n) {
    char* p = (char*)buf;
    while (n) {
        ssize_t r = read(fd, p, n);
        if (r <= 0) return false;
        p += r;
        n -= r;
    }
    return true;
}
static std::string read_whole_file(const std::string& path) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return "";
    std::string out;
    char buf[65536];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) out.append(buf, n);
    close(fd);
    return out;
}

static void inject_client(int fd) {
    uint32_t plen = 0;
    if (!sock_read_full(fd, &plen, 4) || plen == 0 || plen > 1024) { close(fd); return; }
    std::string pkg(plen, 0);
    if (!sock_read_full(fd, &pkg[0], plen)) { close(fd); return; }
    for (char c : pkg)
        if (!(isalnum((unsigned char)c) || c == '.' || c == '_')) { close(fd); return; }

    std::string cfg = read_whole_file(g_hooks_dir + "/" + pkg + ".json");
    uint8_t has = cfg.empty() ? 0 : 1;
    if (!sock_write_full(fd, &has, 1) || !has) { close(fd); return; }

    // 只下发 hook 配置；shadowhook 库由注入层从 /system/lib64 按名加载
    uint32_t clen = (uint32_t)cfg.size();
    if (!sock_write_full(fd, &clen, 4) || !sock_write_full(fd, cfg.data(), clen)) { close(fd); return; }

    log_line("注入层已连接：" + pkg + "（配置 " + std::to_string(clen) + " 字节）");
    // 回传通道：分帧 [type:1][len:4][payload]。'E'=事件JSON(广播)，'D'=内存 dump(落盘)
    while (true) {
        char type = 0;
        if (!sock_read_full(fd, &type, 1)) break;
        uint32_t len = 0;
        if (!sock_read_full(fd, &len, 4) || len > (64u << 20)) break;
        std::string payload(len, 0);
        if (len && !sock_read_full(fd, &payload[0], len)) break;
        if (type == 'E') {
            g_broadcaster.broadcast(payload);
        } else if (type == 'D') {
            // payload = [namelen:2][name][data]
            if (payload.size() < 2) continue;
            uint16_t nl = 0;
            memcpy(&nl, payload.data(), 2);
            if ((size_t)2 + nl > payload.size()) continue;
            std::string name = payload.substr(2, nl);
            // 消毒文件名（只留安全字符）
            std::string safe;
            for (char c : name)
                safe.push_back((isalnum((unsigned char)c) || c == '.' || c == '_' || c == '-') ? c : '_');
            std::string data = payload.substr(2 + nl);
            std::string path = g_dumps_dir + "/" + safe;
            int df = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (df >= 0) {
                (void)!write(df, data.data(), data.size());
                close(df);
                log_line("dump 落盘：" + safe + "（" + std::to_string(data.size()) + " 字节）");
                // 也广播一条通知，便于 PC 侧感知
                g_broadcaster.broadcast(std::string("{\"event\":\"dump_saved\",\"name\":\"") + safe +
                                        "\",\"bytes\":" + std::to_string(data.size()) + "}");
            }
        }
    }
    close(fd);
}

static void inject_server() {
    int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (lfd < 0) return;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = 0;  // 抽象命名空间
    strncpy(addr.sun_path + 1, kInjectSock, sizeof(addr.sun_path) - 2);
    socklen_t len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(kInjectSock);
    if (bind(lfd, (struct sockaddr*)&addr, len) < 0) {
        log_line("inject socket bind 失败");
        close(lfd);
        return;
    }
    listen(lfd, 16);
    log_line(std::string("inject socket @") + kInjectSock + " 就绪");
    while (true) {
        int cfd = accept(lfd, nullptr, nullptr);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            break;
        }
        std::thread(inject_client, cfd).detach();
    }
    close(lfd);
}

// ---------------------------------------------------------------------------
// HTTP 处理：/hook /unhook /hooks /events(SSE)
// ---------------------------------------------------------------------------
static void reply(Response& res, int status, const json& j) {
    res.status = status;
    res.set_content(j.dump(2), "application/json; charset=utf-8");
}

static std::string hook_path(const std::string& pkg) {
    return g_hooks_dir + "/" + pkg + ".json";
}

static void handle_hook(const Request& req, Response& res) {
    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        reply(res, 400, {{"error", "body 非合法 JSON"}});
        return;
    }
    std::string pkg = body.value("package", "");
    if (!valid_pkg(pkg)) {
        reply(res, 400, {{"error", "invalid or missing package"}});
        return;
    }
    if (!body.contains("targets") || !body["targets"].is_array() || body["targets"].empty()) {
        reply(res, 400, {{"error", "targets 不能为空"}});
        return;
    }
    // 给缺 id 的 target 补一个
    int idx = 0;
    for (auto& t : body["targets"]) {
        if (!t.contains("id") || !t["id"].is_string() || t["id"].get<std::string>().empty())
            t["id"] = "h" + std::to_string(idx);
        idx++;
    }
    // 落盘
    ::mkdir(g_hooks_dir.c_str(), 0755);
    {
        std::ofstream f(hook_path(pkg), std::ios::trunc);
        f << body.dump(2);
    }
    std::string note = "配置已写入，注入将在目标下次启动时生效";
    if (body.value("restart", false)) {
        run_detached({"am", "force-stop", pkg});
        note = "配置已写入，并已 force-stop 目标以触发重新注入";
    }
    json installed = json::array();
    for (auto& t : body["targets"]) installed.push_back({{"id", t["id"]}});
    reply(res, 200, {{"ok", true}, {"package", pkg}, {"installed", installed}, {"note", note}});
}

static void handle_unhook(const Request& req, Response& res) {
    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        reply(res, 400, {{"error", "body 非合法 JSON"}});
        return;
    }
    std::string pkg = body.value("package", "");
    if (!valid_pkg(pkg)) {
        reply(res, 400, {{"error", "invalid package"}});
        return;
    }
    std::string p = hook_path(pkg);
    if (body.contains("id") && body["id"].is_string()) {
        // 只移除某个 target
        std::string id = body["id"];
        std::ifstream in(p);
        if (!in.good()) {
            reply(res, 404, {{"error", "该包无 hook 配置"}});
            return;
        }
        json cfg;
        try {
            in >> cfg;
        } catch (...) {
            reply(res, 500, {{"error", "配置损坏"}});
            return;
        }
        json kept = json::array();
        for (auto& t : cfg["targets"])
            if (t.value("id", "") != id) kept.push_back(t);
        if (kept.empty()) {
            ::remove(p.c_str());
        } else {
            cfg["targets"] = kept;
            std::ofstream out(p, std::ios::trunc);
            out << cfg.dump(2);
        }
        reply(res, 200, {{"ok", true}, {"package", pkg}, {"removed_id", id}});
        return;
    }
    // 移除整个包
    bool existed = (::remove(p.c_str()) == 0);
    reply(res, 200, {{"ok", true}, {"package", pkg}, {"removed", existed}});
}

static void handle_hooks(const Request&, Response& res) {
    json arr = json::array();
    DIR* d = opendir(g_hooks_dir.c_str());
    if (d) {
        struct dirent* e;
        while ((e = readdir(d)) != nullptr) {
            std::string name = e->d_name;
            if (name.size() < 6 || name.substr(name.size() - 5) != ".json") continue;
            std::ifstream in(g_hooks_dir + "/" + name);
            if (!in.good()) continue;
            try {
                json cfg;
                in >> cfg;
                arr.push_back(cfg);
            } catch (...) {
            }
        }
        closedir(d);
    }
    reply(res, 200, {{"count", arr.size()}, {"hooks", arr}});
}

static void handle_events_sse(const Request&, Response& res) {
    auto sub = g_broadcaster.subscribe();
    res.set_header("Cache-Control", "no-cache");
    res.set_header("X-Accel-Buffering", "no");
    res.set_chunked_content_provider(
        "text/event-stream",
        [sub](size_t, DataSink& sink) -> bool {
            std::string line;
            if (sub->pop(line, 15000)) {
                std::string chunk = "data: " + line + "\n\n";
                if (!sink.write(chunk.data(), chunk.size())) return false;
            } else {
                static const char* ping = ": ping\n\n";
                if (!sink.write(ping, strlen(ping))) return false;
            }
            return true;
        },
        [sub](bool) { g_broadcaster.unsubscribe(sub); });
}

// POST /dump_dex —— 便捷封装：下发一个“命中即 dump 内存区”的 hook 配置。
// body: {package, lib, symbol|offset, base_arg, size_arg, max?, ext?, restart?}
// 语义：hook 到 dex 加载入口（如 libart 的 OpenMemory/DexFile 构造），命中时把
// [x_base_arg, +x_size_arg) 内存回传落盘（内存中已解密的 dex）。模块侧仍是通用执行器。
static void handle_dump_dex(const Request& req, Response& res) {
    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        reply(res, 400, {{"error", "body 非合法 JSON"}});
        return;
    }
    std::string pkg = body.value("package", "");
    if (!valid_pkg(pkg)) {
        reply(res, 400, {{"error", "invalid or missing package"}});
        return;
    }
    if (!body.contains("base_arg") || !body.contains("size_arg")) {
        reply(res, 400, {{"error", "需要 base_arg 与 size_arg（dex 内存基址/长度所在参数下标）"}});
        return;
    }
    json target = {
        {"id", body.value("id", std::string("dexdump"))},
        {"lib", body.value("lib", "libart.so")},
        {"capture", {{"dump", {{"base_arg", body["base_arg"]},
                               {"size_arg", body["size_arg"]},
                               {"max", body.value("max", 32 * 1024 * 1024)},
                               {"ext", body.value("ext", std::string("dex"))}}}}},
        {"action", {{"type", "observe"}}}};
    if (body.contains("symbol")) target["symbol"] = body["symbol"];
    if (body.contains("offset")) target["offset"] = body["offset"];
    if (!body.contains("symbol") && !body.contains("offset")) {
        reply(res, 400, {{"error", "需要 symbol 或 offset 指定 dex 加载入口"}});
        return;
    }
    json cfg = {{"package", pkg}, {"restart", body.value("restart", false)},
                {"targets", json::array({target})}};
    ::mkdir(g_hooks_dir.c_str(), 0755);
    { std::ofstream f(hook_path(pkg), std::ios::trunc); f << cfg.dump(2); }
    std::string note = "已下发 dump 配置，命中即回传落盘到 dumps/；注入在目标下次启动时生效";
    if (body.value("restart", false)) {
        run_detached({"am", "force-stop", pkg});
        note = "已下发 dump 配置，并 force-stop 目标触发重注入";
    }
    reply(res, 200, {{"ok", true}, {"package", pkg}, {"note", note}, {"config", cfg}});
}

// GET /dumps —— 列出已落盘的 dump 文件（用 /file?path= 下载）
static void handle_dumps(const Request&, Response& res) {
    json arr = json::array();
    DIR* d = opendir(g_dumps_dir.c_str());
    if (d) {
        struct dirent* e;
        while ((e = readdir(d)) != nullptr) {
            std::string name = e->d_name;
            if (name == "." || name == "..") continue;
            std::string full = g_dumps_dir + "/" + name;
            struct stat st;
            long size = (stat(full.c_str(), &st) == 0) ? (long)st.st_size : -1;
            arr.push_back({{"name", name}, {"path", full}, {"size", size}});
        }
        closedir(d);
    }
    reply(res, 200, {{"count", arr.size()}, {"dir", g_dumps_dir}, {"dumps", arr}});
}

void register_routes(httplib::Server& svr) {
    svr.Post("/hook", handle_hook);
    svr.Post("/unhook", handle_unhook);
    svr.Get("/hooks", handle_hooks);
    svr.Post("/dump_dex", handle_dump_dex);
    svr.Get("/dumps", handle_dumps);
    svr.Get("/events", handle_events_sse);  // SSE
}

// ---------------------------------------------------------------------------
// 极简 WebSocket 服务（独立端口 = http_port+1），只做服务端→客户端文本推流
// ---------------------------------------------------------------------------
// --- SHA1（用于握手）---
namespace sha1impl {
struct CTX {
    uint32_t h[5];
    uint64_t len;
    unsigned char buf[64];
    size_t idx;
};
static inline uint32_t rol(uint32_t v, int b) { return (v << b) | (v >> (32 - b)); }
static void init(CTX& c) {
    c.h[0] = 0x67452301;
    c.h[1] = 0xEFCDAB89;
    c.h[2] = 0x98BADCFE;
    c.h[3] = 0x10325476;
    c.h[4] = 0xC3D2E1F0;
    c.len = 0;
    c.idx = 0;
}
static void block(CTX& c, const unsigned char* p) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
        w[i] = (p[i * 4] << 24) | (p[i * 4 + 1] << 16) | (p[i * 4 + 2] << 8) | p[i * 4 + 3];
    for (int i = 16; i < 80; i++) w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    uint32_t a = c.h[0], b = c.h[1], d = c.h[2], e = c.h[3], f = c.h[4];
    for (int i = 0; i < 80; i++) {
        uint32_t k, t;
        if (i < 20) { t = (b & d) | ((~b) & e); k = 0x5A827999; }
        else if (i < 40) { t = b ^ d ^ e; k = 0x6ED9EBA1; }
        else if (i < 60) { t = (b & d) | (b & e) | (d & e); k = 0x8F1BBCDC; }
        else { t = b ^ d ^ e; k = 0xCA62C1D6; }
        uint32_t tmp = rol(a, 5) + t + f + k + w[i];
        f = e; e = d; d = rol(b, 30); b = a; a = tmp;
    }
    c.h[0] += a; c.h[1] += b; c.h[2] += d; c.h[3] += e; c.h[4] += f;
}
static void update(CTX& c, const unsigned char* p, size_t n) {
    c.len += n * 8;
    for (size_t i = 0; i < n; i++) {
        c.buf[c.idx++] = p[i];
        if (c.idx == 64) { block(c, c.buf); c.idx = 0; }
    }
}
static void final(CTX& c, unsigned char out[20]) {
    unsigned char pad = 0x80;
    uint64_t l = c.len;
    update(c, &pad, 1);
    unsigned char z = 0;
    while (c.idx != 56) update(c, &z, 1);
    unsigned char lb[8];
    for (int i = 0; i < 8; i++) lb[i] = (l >> (56 - i * 8)) & 0xff;
    // 直接写入而不再递增 len
    for (int i = 0; i < 8; i++) {
        c.buf[c.idx++] = lb[i];
        if (c.idx == 64) { block(c, c.buf); c.idx = 0; }
    }
    for (int i = 0; i < 5; i++) {
        out[i * 4] = (c.h[i] >> 24) & 0xff;
        out[i * 4 + 1] = (c.h[i] >> 16) & 0xff;
        out[i * 4 + 2] = (c.h[i] >> 8) & 0xff;
        out[i * 4 + 3] = c.h[i] & 0xff;
    }
}
}  // namespace sha1impl

static std::string base64(const unsigned char* p, size_t n) {
    static const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string o;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = p[i] << 16;
        if (i + 1 < n) v |= p[i + 1] << 8;
        if (i + 2 < n) v |= p[i + 2];
        o.push_back(t[(v >> 18) & 63]);
        o.push_back(t[(v >> 12) & 63]);
        o.push_back(i + 1 < n ? t[(v >> 6) & 63] : '=');
        o.push_back(i + 2 < n ? t[v & 63] : '=');
    }
    return o;
}

static std::atomic<int> g_ws_listen_fd{-1};
static std::atomic<bool> g_ws_running{false};
static std::thread g_ws_thread;
static std::string g_token_for_ws;  // 由 daemon 在启动时通过环境或直接读配置获得

// 从 config.conf 读 token（WS 鉴权用；与 HTTP 独立，简单读一次）
static std::string read_token() {
    std::ifstream f(g_base_dir + "/config.conf");
    std::string line;
    while (std::getline(f, line)) {
        auto eq = line.find('=');
        if (eq != std::string::npos && line.substr(0, eq) == "token")
            return line.substr(eq + 1);
    }
    return "";
}

static void ws_send_text(int fd, const std::string& msg) {
    std::string frame;
    frame.push_back((char)0x81);  // FIN + text
    size_t n = msg.size();
    if (n < 126) {
        frame.push_back((char)n);
    } else if (n < 65536) {
        frame.push_back((char)126);
        frame.push_back((char)((n >> 8) & 0xff));
        frame.push_back((char)(n & 0xff));
    } else {
        frame.push_back((char)127);
        for (int i = 7; i >= 0; i--) frame.push_back((char)((n >> (i * 8)) & 0xff));
    }
    frame += msg;
    ::send(fd, frame.data(), frame.size(), MSG_NOSIGNAL);
}

static void ws_handle_client(int fd) {
    // 读 HTTP 升级请求
    std::string reqbuf;
    char buf[2048];
    while (reqbuf.find("\r\n\r\n") == std::string::npos) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) { close(fd); return; }
        reqbuf.append(buf, n);
        if (reqbuf.size() > 16384) break;
    }
    // 解析 Sec-WebSocket-Key 与 token（?token= 或 header）
    auto header = [&](const char* name) -> std::string {
        std::string key = name;
        size_t p = reqbuf.find(key);
        if (p == std::string::npos) return "";
        p += key.size();
        size_t e = reqbuf.find("\r\n", p);
        std::string v = reqbuf.substr(p, e - p);
        size_t s = v.find_first_not_of(" ");
        return s == std::string::npos ? "" : v.substr(s);
    };
    std::string wskey = header("Sec-WebSocket-Key:");
    // token：从请求行 query 里取
    std::string token;
    {
        size_t p = reqbuf.find("token=");
        if (p != std::string::npos) {
            p += 6;
            size_t e = reqbuf.find_first_of(" &\r\n", p);
            token = reqbuf.substr(p, e - p);
        }
    }
    if (wskey.empty() || token.empty() || token != g_token_for_ws) {
        const char* resp = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
        ::send(fd, resp, strlen(resp), MSG_NOSIGNAL);
        close(fd);
        return;
    }
    // 计算 accept
    std::string accept_src = wskey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    sha1impl::CTX c;
    sha1impl::init(c);
    sha1impl::update(c, (const unsigned char*)accept_src.data(), accept_src.size());
    unsigned char dig[20];
    sha1impl::final(c, dig);
    std::string accept = base64(dig, 20);
    std::string resp = "HTTP/1.1 101 Switching Protocols\r\n"
                       "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                       "Sec-WebSocket-Accept: " + accept + "\r\n\r\n";
    if (::send(fd, resp.data(), resp.size(), MSG_NOSIGNAL) < 0) { close(fd); return; }

    // 订阅事件并推流；同时非阻塞检测客户端关闭
    auto sub = g_broadcaster.subscribe();
    fcntl(fd, F_SETFL, O_NONBLOCK);
    bool alive = true;
    while (alive && g_ws_running) {
        std::string line;
        if (sub->pop(line, 5000)) {
            ws_send_text(fd, line);
        } else {
            // ping（opcode 0x9）保活
            char p[2] = {(char)0x89, 0};
            if (::send(fd, p, 2, MSG_NOSIGNAL) < 0) alive = false;
        }
        // 探测对端关闭
        char t[512];
        ssize_t n = recv(fd, t, sizeof(t), MSG_DONTWAIT);
        if (n == 0) alive = false;
        else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) alive = false;
        else if (n >= 1 && (t[0] & 0x0f) == 0x08) alive = false;  // close 帧
    }
    g_broadcaster.unsubscribe(sub);
    close(fd);
}

static void ws_accept_loop(std::string host, int port) {
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) return;
    int opt = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (host == "0.0.0.0" || host.empty())
        addr.sin_addr.s_addr = INADDR_ANY;
    else
        inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    if (bind(lfd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        log_line("WS bind 失败 " + host + ":" + std::to_string(port));
        close(lfd);
        return;
    }
    listen(lfd, 8);
    g_ws_listen_fd = lfd;
    log_line("WS 服务监听 " + host + ":" + std::to_string(port));
    while (g_ws_running) {
        int cfd = accept(lfd, nullptr, nullptr);
        if (cfd < 0) {
            if (!g_ws_running) break;
            continue;
        }
        std::thread(ws_handle_client, cfd).detach();
    }
    close(lfd);
    g_ws_listen_fd = -1;
}

void on_server_start(const std::string& host, int http_port) {
    g_token_for_ws = read_token();
    g_ws_running = true;
    g_ws_thread = std::thread(ws_accept_loop, host, http_port + 1);
}

void on_server_stop() {
    g_ws_running = false;
    int fd = g_ws_listen_fd.load();
    if (fd >= 0) shutdown(fd, SHUT_RDWR);  // 唤醒 accept
    if (g_ws_thread.joinable()) g_ws_thread.join();
}

// ---------------------------------------------------------------------------
void init(const std::string& base_dir) {
    g_base_dir = base_dir;
    g_hooks_dir = base_dir + "/hooks";
    g_events_log = base_dir + "/events.log";
    g_dumps_dir = base_dir + "/dumps";
    ::mkdir(g_hooks_dir.c_str(), 0755);
    ::mkdir(g_dumps_dir.c_str(), 0755);
    // 确保 events.log 存在（保留旧的 file-tail 兜底路径）
    { std::ofstream f(g_events_log, std::ios::app); }
    std::thread(events_watcher).detach();
    // 注入 IPC 抽象 socket（注入层直连守护进程取配置/回传事件）
    std::thread(inject_server).detach();
}

}  // namespace dynamic

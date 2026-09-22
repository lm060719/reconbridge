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

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <fstream>
#include <future>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
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
static std::string g_programs_dir;
static std::string g_program_policy_dir;
static std::mutex g_program_mutex;

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

    // 环形缓冲：保留最近 N 条事件，供 GET /recent 事后采集（P0-1）——
    // 命中即便发生在 SSE 采集开始之前，也能事后补捞，不必"掐点"连着流。
    std::mutex ring_m_;
    std::deque<std::pair<uint64_t, std::string>> ring_;
    uint64_t seq_ = 0;
    static constexpr size_t kRingMax = 400;

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
        {   // 先入环形缓冲（独立锁，不与订阅者分发互相阻塞）
            std::lock_guard<std::mutex> lk(ring_m_);
            ring_.push_back({++seq_, line});
            while (ring_.size() > kRingMax) ring_.pop_front();
        }
        std::lock_guard<std::mutex> lk(m_);
        for (auto& s : subs_) s->push(line);
    }
    size_t count() {
        std::lock_guard<std::mutex> lk(m_);
        return subs_.size();
    }

    // 取缓冲里 seq>since 的事件，最多保留最新 limit 条（limit=0 只用于取游标）。
    std::vector<std::pair<uint64_t, std::string>> recent(uint64_t since, size_t limit) {
        std::lock_guard<std::mutex> lk(ring_m_);
        std::vector<std::pair<uint64_t, std::string>> out;
        for (auto& e : ring_)
            if (e.first > since) out.push_back(e);
        if (out.size() > limit) out.erase(out.begin(), out.begin() + (out.size() - limit));
        return out;
    }
    uint64_t latest_seq() {
        std::lock_guard<std::mutex> lk(ring_m_);
        return seq_;
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

// ---------------------------------------------------------------------------
// LSPosed Runtime Phase 1：注入连接注册表 + 实时配置同步。
// 每个 tracer 连接注册进来；'H' 声明支持 live reconcile，daemon 用 'R' 下发完整期望配置。
// tracer 的 HookRegistry 据此执行 add/remove/replace，并通过 'S' 帧回报真实运行时状态。
// native 层不发 'H'/'S'，仍保持原有下次启动/重启生效语义。
// ---------------------------------------------------------------------------
struct RuntimeCommandWaiter {
    std::mutex m;
    std::condition_variable cv;
    bool done = false;
    json response = nullptr;
};

struct InjectConn {
    int fd;
    std::string base_pkg;
    std::string process_name;
    std::mutex write_mutex;
    bool alive = true;
    bool reload_capable = false;
    bool command_capable = false;
    json runtime_status = nullptr;
    int64_t status_updated_at = 0;
    std::mutex command_mutex;
    std::unordered_map<std::string, std::shared_ptr<RuntimeCommandWaiter>> command_waiters;
};
static std::mutex g_conn_mutex;
static std::vector<std::shared_ptr<InjectConn>> g_conns;

static void reg_add(const std::shared_ptr<InjectConn>& c) {
    std::lock_guard<std::mutex> lk(g_conn_mutex);
    g_conns.push_back(c);
}
static void reg_remove(const std::shared_ptr<InjectConn>& c) {
    std::lock_guard<std::mutex> lk(g_conn_mutex);
    for (auto it = g_conns.begin(); it != g_conns.end(); ++it)
        if (*it == c) { g_conns.erase(it); break; }
}
static void reg_mark_reloadable(const std::shared_ptr<InjectConn>& c) {
    std::lock_guard<std::mutex> lk(g_conn_mutex);
    c->reload_capable = true;
}

static void reg_mark_command_capable(const std::shared_ptr<InjectConn>& c) {
    std::lock_guard<std::mutex> lk(g_conn_mutex);
    c->command_capable = true;
}

static void reg_handle_command_ack(
    const std::shared_ptr<InjectConn>& c,
    const std::string& payload) {
    json ack;
    try {
        ack = json::parse(payload);
    } catch (...) {
        log_line("Tracer Runtime Command Ack 解析失败：" + c->process_name);
        return;
    }

    const std::string request_id = ack.value("request_id", "");
    if (request_id.empty()) return;

    std::shared_ptr<RuntimeCommandWaiter> waiter;
    {
        std::lock_guard<std::mutex> lk(c->command_mutex);
        auto it = c->command_waiters.find(request_id);
        if (it == c->command_waiters.end()) return;
        waiter = it->second;
    }

    {
        std::lock_guard<std::mutex> lk(waiter->m);
        waiter->response = std::move(ack);
        waiter->done = true;
    }
    waiter->cv.notify_all();
}

static void reg_fail_pending_commands(
    const std::shared_ptr<InjectConn>& c,
    const std::string& reason) {
    std::vector<std::shared_ptr<RuntimeCommandWaiter>> waiters;
    {
        std::lock_guard<std::mutex> lk(c->command_mutex);
        for (const auto& item : c->command_waiters)
            waiters.push_back(item.second);
    }

    for (const auto& waiter : waiters) {
        {
            std::lock_guard<std::mutex> lk(waiter->m);
            if (waiter->done) continue;
            waiter->response = {
                {"ok", false},
                {"error", reason}
            };
            waiter->done = true;
        }
        waiter->cv.notify_all();
    }
}
static int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

static void reg_update_status(const std::shared_ptr<InjectConn>& c, const std::string& payload) {
    json status;
    try {
        status = json::parse(payload);
    } catch (...) {
        log_line("Tracer runtime status 解析失败：" + c->process_name);
        return;
    }
    std::lock_guard<std::mutex> lk(g_conn_mutex);
    if (status.contains("process") && status["process"].is_string()) {
        c->process_name = status["process"].get<std::string>();
    }
    c->runtime_status = std::move(status);
    c->status_updated_at = now_ms();
}

static json runtime_status_snapshot(const std::string& package_filter) {
    json processes = json::array();
    std::lock_guard<std::mutex> lk(g_conn_mutex);
    for (const auto& c : g_conns) {
        if (!package_filter.empty() && c->base_pkg != package_filter)
            continue;
        json row = {
            {"package", c->base_pkg},
            {"process", c->process_name},
            {"connected", true},
            {"live_reconcile", c->reload_capable},
            {"runtime_command", c->command_capable},
            {"status_updated_at", c->status_updated_at}
        };
        if (!c->runtime_status.is_null())
            row["runtime"] = c->runtime_status;
        else
            row["runtime"] = nullptr;
        processes.push_back(std::move(row));
    }
    return {
        {"count", processes.size()},
        {"package", package_filter.empty() ? json(nullptr) : json(package_filter)},
        {"processes", processes}
    };
}

// 向某包所有支持 live reconcile 的 tracer 下发 'R'，payload=完整期望配置 JSON。
static int hot_reload(const std::string& base_pkg, const std::string& cfg) {
    std::vector<std::shared_ptr<InjectConn>> targets;
    {
        std::lock_guard<std::mutex> lk(g_conn_mutex);
        for (const auto& c : g_conns) {
            if (c->base_pkg == base_pkg && c->reload_capable)
                targets.push_back(c);
        }
    }

    int n = 0;
    char hdr[5];
    uint32_t l = (uint32_t)cfg.size();
    hdr[0] = 'R';
    memcpy(hdr + 1, &l, 4);

    for (const auto& c : targets) {
        std::lock_guard<std::mutex> write_lk(c->write_mutex);
        if (!c->alive)
            continue;
        if (sock_write_full(c->fd, hdr, 5) &&
            (l == 0 || sock_write_full(c->fd, cfg.data(), l))) {
            n++;
        }
    }
    return n;
}

static std::atomic<uint64_t> g_runtime_command_seq{1};

static json send_runtime_command_to_conn(
    const std::shared_ptr<InjectConn>& c,
    json command,
    int timeout_ms) {
    std::string process_name_snapshot;
    {
        std::lock_guard<std::mutex> lk(g_conn_mutex);
        process_name_snapshot = c->process_name;
    }

    const uint64_t seq = g_runtime_command_seq.fetch_add(1);
    const std::string request_id =
        "rcmd_" + std::to_string(now_ms()) + "_" + std::to_string(seq);
    command["request_id"] = request_id;

    auto waiter = std::make_shared<RuntimeCommandWaiter>();
    {
        std::lock_guard<std::mutex> lk(c->command_mutex);
        c->command_waiters[request_id] = waiter;
    }

    const std::string payload = command.dump();
    const uint32_t len = static_cast<uint32_t>(payload.size());
    char hdr[5];
    hdr[0] = 'C';
    memcpy(hdr + 1, &len, 4);

    bool sent = false;
    {
        std::lock_guard<std::mutex> write_lk(c->write_mutex);
        if (c->alive) {
            sent = sock_write_full(c->fd, hdr, sizeof(hdr)) &&
                   (len == 0 || sock_write_full(
                       c->fd,
                       payload.data(),
                       payload.size()));
        }
    }

    if (!sent) {
        std::lock_guard<std::mutex> lk(c->command_mutex);
        c->command_waiters.erase(request_id);
        return {
            {"ok", false},
            {"request_id", request_id},
            {"error", "Runtime Command 发送失败"}
        };
    }

    json response;
    {
        std::unique_lock<std::mutex> lk(waiter->m);
        const bool ready = waiter->cv.wait_for(
            lk,
            std::chrono::milliseconds(timeout_ms),
            [&] { return waiter->done; });
        if (!ready) {
            response = {
                {"ok", false},
                {"request_id", request_id},
                {"error", "Runtime Command Ack 超时"}
            };
        } else {
            response = waiter->response;
        }
    }

    {
        std::lock_guard<std::mutex> lk(c->command_mutex);
        c->command_waiters.erase(request_id);
    }

    if (!response.is_object()) {
        response = {
            {"ok", false},
            {"request_id", request_id},
            {"error", "Runtime Command Ack 格式无效"}
        };
    }
    if (!response.contains("request_id"))
        response["request_id"] = request_id;
    response["package"] = c->base_pkg;
    response["process"] = process_name_snapshot;
    return response;
}

static json dispatch_runtime_command_internal(
    const std::string& pkg,
    const std::string& process,
    json command,
    int timeout_ms) {
    if (timeout_ms < 200) timeout_ms = 200;
    if (timeout_ms > 10000) timeout_ms = 10000;
    command["_timeout_ms"] = timeout_ms;

    std::vector<std::shared_ptr<InjectConn>> targets;
    {
        std::lock_guard<std::mutex> lk(g_conn_mutex);
        for (const auto& conn : g_conns) {
            if (conn->base_pkg != pkg || !conn->command_capable)
                continue;
            if (!process.empty() && conn->process_name != process)
                continue;
            targets.push_back(conn);
        }
    }

    if (targets.empty()) {
        return {
            {"ok", false},
            {"package", pkg},
            {"process", process.empty() ? json(nullptr) : json(process)},
            {"targeted", 0},
            {"succeeded", 0},
            {"op", command.value("op", "")},
            {"error", "没有在线且支持 Runtime Command 的 Tracer 进程"}
        };
    }

    std::vector<std::future<json>> futures;
    futures.reserve(targets.size());
    for (const auto& conn : targets) {
        futures.push_back(std::async(
            std::launch::async,
            [conn, command, timeout_ms]() mutable {
                return send_runtime_command_to_conn(
                    conn,
                    command,
                    timeout_ms);
            }));
    }

    json results = json::array();
    size_t succeeded = 0;
    for (auto& future : futures) {
        json result;
        try {
            result = future.get();
        } catch (const std::exception& e) {
            result = {
                {"ok", false},
                {"error", e.what()}
            };
        } catch (...) {
            result = {
                {"ok", false},
                {"error", "Runtime Command 未知异常"}
            };
        }
        if (result.value("ok", false))
            ++succeeded;
        results.push_back(std::move(result));
    }

    return {
        {"ok", succeeded > 0},
        {"package", pkg},
        {"process", process.empty() ? json(nullptr) : json(process)},
        {"targeted", targets.size()},
        {"succeeded", succeeded},
        {"op", command.value("op", "")},
        {"results", results}
    };
}

static void inject_client(int fd) {
    uint32_t plen = 0;
    if (!sock_read_full(fd, &plen, 4) || plen == 0 || plen > 1024) { close(fd); return; }
    std::string pkg(plen, 0);
    if (!sock_read_full(fd, &pkg[0], plen)) { close(fd); return; }
    // Android 子进程名形如 "pkg:suffix"（如 com.foo:core），必须放行冒号，
    // 否则子进程（往往才是真正干活的进程）连接会在这里被静默拒绝，且不落日志。
    for (char c : pkg)
        if (!(isalnum((unsigned char)c) || c == '.' || c == '_' || c == ':')) { close(fd); return; }

    // hook 配置文件按主包名（去掉 :suffix）查找，子进程复用同一份配置
    std::string base_pkg = pkg;
    size_t colon = base_pkg.find(':');
    if (colon != std::string::npos) base_pkg = base_pkg.substr(0, colon);

    std::string cfg = read_whole_file(g_hooks_dir + "/" + base_pkg + ".json");
    uint8_t has = cfg.empty() ? 0 : 1;
    if (!sock_write_full(fd, &has, 1) || !has) {
        log_line("注入层已连接但无配置：" + pkg);
        close(fd);
        return;
    }

    // 只下发 hook 配置；shadowhook 库由注入层从 /system/lib64 按名加载
    uint32_t clen = (uint32_t)cfg.size();
    if (!sock_write_full(fd, &clen, 4) || !sock_write_full(fd, cfg.data(), clen)) { close(fd); return; }

    log_line("注入层已连接：" + pkg + "（配置 " + std::to_string(clen) + " 字节）");
    // 注册进连接表，供 /hook 热加下发 'R' 帧定位（按主包名）
    auto conn = std::make_shared<InjectConn>();
    conn->fd = fd;
    conn->base_pkg = base_pkg;
    conn->process_name = pkg;
    reg_add(conn);
    // 回传通道：
    // 'E'=事件，'D'=dump，'H'=声明 live reconcile，'S'=Runtime status，
    // 'K'=声明 Runtime Command，'A'=Runtime Command Ack。
    while (true) {
        char type = 0;
        if (!sock_read_full(fd, &type, 1)) break;
        uint32_t len = 0;
        if (!sock_read_full(fd, &len, 4) || len > (64u << 20)) break;
        std::string payload(len, 0);
        if (len && !sock_read_full(fd, &payload[0], len)) break;
        if (type == 'H') {
            reg_mark_reloadable(conn);
            log_line("Tracer 声明支持 live reconcile：" + pkg);
        } else if (type == 'K') {
            reg_mark_command_capable(conn);
            log_line("Tracer 声明支持 Runtime Command：" + pkg);
        } else if (type == 'A') {
            reg_handle_command_ack(conn, payload);
        } else if (type == 'S') {
            reg_update_status(conn, payload);
        } else if (type == 'E') {
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
    reg_remove(conn);
    reg_fail_pending_commands(
        conn,
        "目标进程 Runtime 通道已断开"
    );
    {
        // 和 hot_reload / runtime command 使用同一把锁，避免并发写撞上 close / fd 复用。
        std::lock_guard<std::mutex> write_lk(conn->write_mutex);
        conn->alive = false;
        close(fd);
    }
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


static bool valid_runtime_program_id(const std::string& value) {
    if (value.empty() || value.size() > 64) return false;
    for (char ch : value) {
        if (!(isalnum((unsigned char)ch) || ch == '.' || ch == '_' || ch == '-'))
            return false;
    }
    return true;
}

static std::string runtime_program_package_dir(const std::string& pkg) {
    return g_programs_dir + "/" + pkg;
}

static std::string runtime_program_path(
    const std::string& pkg,
    const std::string& program_id) {
    return runtime_program_package_dir(pkg) + "/" + program_id + ".json";
}

static bool read_json_file(const std::string& path, json& out) {
    std::ifstream in(path);
    if (!in.good()) return false;
    try {
        in >> out;
        return true;
    } catch (...) {
        return false;
    }
}

static bool write_json_atomic(
    const std::string& path,
    const json& value) {
    const std::string tmp =
        path + ".tmp." + std::to_string((long long)getpid());
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out.good()) return false;
        out << value.dump(2);
        out.flush();
        if (!out.good()) {
            ::remove(tmp.c_str());
            return false;
        }
    }
    if (::rename(tmp.c_str(), path.c_str()) != 0) {
        ::remove(tmp.c_str());
        return false;
    }
    return true;
}

static std::string normalize_program_scope(
    const std::string& raw) {
    if (raw.empty() || raw == "global") return "process";
    if (raw == "pkg") return "package";
    return raw;
}

static const std::set<std::string>& runtime_program_known_permissions() {
    static const std::set<std::string> values = {
        "hook.java",
        "hook.tamper",
        "runtime.event",
        "runtime.lifecycle",
        "state.write",
        "java.call",
        "java.field_write",
        "java.construct",
        "code.eval_js",
        "code.eval_dex",
        "shell.exec",
        "shell.root",
        "activity.access"
    };
    return values;
}

static void collect_runtime_program_permissions(
    const json& node,
    std::set<std::string>& out) {
    if (node.is_array()) {
        for (const auto& item : node)
            collect_runtime_program_permissions(item, out);
        return;
    }
    if (!node.is_object()) return;

    if (node.contains("kind") && node["kind"].is_string()) {
        const std::string kind = node["kind"].get<std::string>();
        if (kind == "java") out.insert("hook.java");
        if (kind == "runtime") {
            if (node.contains("on_event") ||
                node.contains("event_handlers"))
                out.insert("runtime.event");
            if (node.contains("on_lifecycle"))
                out.insert("runtime.lifecycle");
        }
    }

    if (node.contains("on_event") ||
        node.contains("event_handlers"))
        out.insert("runtime.event");
    if (node.contains("on_lifecycle"))
        out.insert("runtime.lifecycle");

    if ((node.contains("state_init") &&
         node["state_init"].is_array() &&
         !node["state_init"].empty()) ||
        (node.contains("state_cleanup") &&
         node["state_cleanup"].is_array() &&
         !node["state_cleanup"].empty()))
        out.insert("state.write");

    if (node.contains("action") && node["action"].is_string()) {
        const std::string action =
            node["action"].get<std::string>();
        if (action == "set_state" ||
            action == "remove_state" ||
            action == "clear_state" ||
            action == "increment_state" ||
            action == "append_state")
            out.insert("state.write");
        else if (action == "call_method" ||
                 action == "invoke")
            out.insert("java.call");
        else if (action == "set_field" ||
                 action == "mutate" ||
                 action == "set_path" ||
                 action == "mutate_path")
            out.insert("java.field_write");
        else if (action == "construct" ||
                 action == "new_instance")
            out.insert("java.construct");
        else if (action == "eval_js" ||
                 action == "js")
            out.insert("code.eval_js");
        else if (action == "eval_dex" ||
                 action == "dex")
            out.insert("code.eval_dex");
        else if (action == "exec_shell" ||
                 action == "shell") {
            out.insert("shell.exec");
            if (node.value("as_root", false))
                out.insert("shell.root");
        } else if (action == "set_arg" ||
                   action == "set_result" ||
                   action == "replace_return")
            out.insert("hook.tamper");
        else if (action == "emit_event")
            out.insert("runtime.event");
    }

    if (node.contains("target") &&
        node["target"].is_string() &&
        node["target"].get<std::string>() == "activity")
        out.insert("activity.access");

    if ((node.contains("replace_args") &&
         !node["replace_args"].is_null()) ||
        node.contains("replace_return") ||
        (node.contains("mutate_return") &&
         !node["mutate_return"].is_null()) ||
        node.value("skip_original", false))
        out.insert("hook.tamper");

    for (auto it = node.begin(); it != node.end(); ++it) {
        if (it.key() == "permissions") continue;
        collect_runtime_program_permissions(it.value(), out);
    }
}

static json runtime_program_permission_array(
    const std::set<std::string>& values) {
    json out = json::array();
    for (const auto& value : values)
        out.push_back(value);
    return out;
}


static std::vector<json> load_runtime_program_records(
    const std::string& pkg);

static std::string runtime_program_policy_path(
    const std::string& pkg) {
    return g_program_policy_dir + "/" + pkg + ".json";
}

static bool valid_program_policy_action(
    const std::string& action) {
    return action == "allow" ||
           action == "ask" ||
           action == "deny";
}

static json default_runtime_program_policy(
    const std::string& pkg) {
    return {
        {"schema", 1},
        {"package", pkg},
        {"default", "allow"},
        {"permissions", json::object()},
        {"approvals", json::object()},
        {"updated_at", (int64_t)0}
    };
}

static json load_runtime_program_policy(
    const std::string& pkg) {
    json policy;
    if (!read_json_file(
            runtime_program_policy_path(pkg),
            policy) ||
        !policy.is_object()) {
        return default_runtime_program_policy(pkg);
    }

    policy["schema"] = 1;
    policy["package"] = pkg;
    if (!policy.contains("default") ||
        !policy["default"].is_string() ||
        !valid_program_policy_action(
            policy["default"].get<std::string>()))
        policy["default"] = "allow";
    if (!policy.contains("permissions") ||
        !policy["permissions"].is_object())
        policy["permissions"] = json::object();
    if (!policy.contains("approvals") ||
        !policy["approvals"].is_object())
        policy["approvals"] = json::object();
    return policy;
}

static std::set<std::string> json_string_set(
    const json& value) {
    std::set<std::string> out;
    if (!value.is_array()) return out;
    for (const auto& item : value) {
        if (item.is_string())
            out.insert(item.get<std::string>());
    }
    return out;
}

static json runtime_program_policy_evaluate(
    const std::string& pkg,
    const std::string& program_id,
    const json& manifest,
    const json& approve_once = json::array()) {
    const json policy = load_runtime_program_policy(pkg);
    const std::string default_action =
        policy.value("default", "allow");
    const json overrides =
        policy.value("permissions", json::object());

    std::set<std::string> required;
    collect_runtime_program_permissions(
        manifest,
        required);

    std::set<std::string> persistent;
    const json approvals =
        policy.value("approvals", json::object());
    if (approvals.is_object() &&
        approvals.contains(program_id))
        persistent = json_string_set(
            approvals[program_id]);

    const auto once =
        json_string_set(approve_once);

    json allowed = json::array();
    json denied = json::array();
    json approval_required = json::array();
    json approved = json::array();
    json decisions = json::object();

    for (const auto& permission : required) {
        std::string action = default_action;
        if (overrides.is_object() &&
            overrides.contains(permission) &&
            overrides[permission].is_string()) {
            const std::string candidate =
                overrides[permission]
                    .get<std::string>();
            if (valid_program_policy_action(
                    candidate))
                action = candidate;
        }
        decisions[permission] = action;

        if (action == "deny") {
            denied.push_back(permission);
            continue;
        }
        if (action == "ask") {
            if (persistent.count(permission) ||
                once.count(permission)) {
                approved.push_back(permission);
                allowed.push_back(permission);
            } else {
                approval_required.push_back(
                    permission);
            }
            continue;
        }
        allowed.push_back(permission);
    }

    std::string decision = "allow";
    if (!denied.empty())
        decision = "deny";
    else if (!approval_required.empty())
        decision = "ask";

    return {
        {"ok", decision == "allow"},
        {"decision", decision},
        {"program_id", program_id},
        {"default", default_action},
        {"required", runtime_program_permission_array(
            required)},
        {"allowed", allowed},
        {"denied", denied},
        {"approval_required", approval_required},
        {"approved", approved},
        {"decisions", decisions}
    };
}

static bool normalize_runtime_program_policy(
    const std::string& pkg,
    const json& input,
    json& normalized,
    std::string& error) {
    if (!input.is_object()) {
        error = "policy 必须是 JSON object";
        return false;
    }

    json current =
        load_runtime_program_policy(pkg);
    normalized = current;
    normalized["schema"] = 1;
    normalized["package"] = pkg;

    if (input.contains("default")) {
        if (!input["default"].is_string()) {
            error =
                "policy.default 必须是 allow/ask/deny";
            return false;
        }
        const std::string action =
            input["default"].get<std::string>();
        if (!valid_program_policy_action(action)) {
            error =
                "policy.default 必须是 allow/ask/deny";
            return false;
        }
        normalized["default"] = action;
    }

    if (input.contains("permissions")) {
        if (!input["permissions"].is_object()) {
            error =
                "policy.permissions 必须是 object";
            return false;
        }
        json overrides = json::object();
        for (auto it =
                 input["permissions"].begin();
             it != input["permissions"].end();
             ++it) {
            if (!runtime_program_known_permissions()
                     .count(it.key())) {
                error =
                    "未知 Runtime Program 权限: " +
                    it.key();
                return false;
            }
            if (!it.value().is_string() ||
                !valid_program_policy_action(
                    it.value().get<std::string>())) {
                error =
                    "权限策略必须是 allow/ask/deny: " +
                    it.key();
                return false;
            }
            overrides[it.key()] = it.value();
        }
        normalized["permissions"] =
            std::move(overrides);
    }

    if (input.value("clear_approvals", false))
        normalized["approvals"] =
            json::object();
    if (!normalized.contains("approvals") ||
        !normalized["approvals"].is_object())
        normalized["approvals"] =
            json::object();

    normalized["updated_at"] = now_ms();
    return true;
}

static json runtime_program_policy_response(
    const std::string& pkg,
    const json& policy) {
    json programs = json::array();
    for (const auto& record :
         load_runtime_program_records(pkg)) {
        const json manifest =
            record.value(
                "manifest",
                json::object());
        json evaluation =
            runtime_program_policy_evaluate(
                pkg,
                record.value("id", ""),
                manifest);
        programs.push_back({
            {"id", record.value("id", "")},
            {"revision",
             record.value("revision", 0)},
            {"enabled",
             record.value("enabled", false)},
            {"effective_enabled",
             record.value("enabled", false) &&
             evaluation.value(
                 "decision",
                 "deny") == "allow"},
            {"policy", evaluation}
        });
    }
    return {
        {"package", pkg},
        {"policy", policy},
        {"programs", programs}
    };
}

static bool normalize_runtime_program_manifest(
    const json& input,
    json& normalized,
    std::string& error) {
    if (!input.is_object()) {
        error = "manifest 必须是 JSON object";
        return false;
    }

    normalized = input;
    const std::string id = normalized.value("id", "");
    if (!valid_runtime_program_id(id)) {
        error = "manifest.id 无效：仅允许 1-64 位字母数字 . _ -";
        return false;
    }

    if (!normalized.contains("name"))
        normalized["name"] = id;
    if (!normalized.contains("version"))
        normalized["version"] = "1";
    if (!normalized["name"].is_string() ||
        !normalized["version"].is_string()) {
        error = "manifest.name / version 必须是字符串";
        return false;
    }

    if (!normalized.contains("targets"))
        normalized["targets"] = json::array();
    if (!normalized["targets"].is_array()) {
        error = "manifest.targets 必须是数组";
        return false;
    }
    if (normalized["targets"].size() > 128) {
        error = "manifest.targets 最多 128 项";
        return false;
    }

    std::set<std::string> local_ids;
    size_t target_index = 0;
    for (auto& target : normalized["targets"]) {
        if (!target.is_object()) {
            error = "manifest.targets 每项必须是 object";
            return false;
        }
        std::string local_id = target.value("id", "");
        if (local_id.empty())
            local_id = "t" + std::to_string(target_index);
        if (!valid_runtime_program_id(local_id) ||
            local_id == "__bootstrap") {
            error = "target.id 无效或使用了保留 id __bootstrap";
            return false;
        }
        if (!local_ids.insert(local_id).second) {
            error = "manifest.targets 存在重复 id: " + local_id;
            return false;
        }
        target["id"] = local_id;

        const std::string kind = target.value("kind", "java");
        if (kind != "java" && kind != "runtime") {
            error = "Runtime Program target 仅支持 kind=java/runtime";
            return false;
        }
        target["kind"] = kind;
        ++target_index;
    }

    for (const char* key : {"state_init", "state_cleanup"}) {
        if (!normalized.contains(key))
            normalized[key] = json::array();
        if (!normalized[key].is_array()) {
            error = std::string("manifest.") + key + " 必须是数组";
            return false;
        }
        if (normalized[key].size() > 128) {
            error = std::string("manifest.") + key + " 最多 128 项";
            return false;
        }
        for (auto& row : normalized[key]) {
            if (!row.is_object()) {
                error = std::string("manifest.") + key + " 每项必须是 object";
                return false;
            }
            const std::string scope =
                normalize_program_scope(row.value("scope", "process"));
            if (scope != "process" && scope != "package") {
                error = std::string("manifest.") + key +
                    " 目前只支持 process/package scope";
                return false;
            }
            const std::string state_key = row.value("key", "");
            if (state_key.empty()) {
                error = std::string("manifest.") + key + ".key 不能为空";
                return false;
            }
            row["scope"] = scope;
            if (std::string(key) == "state_init" &&
                !row.contains("value")) {
                row["value"] = nullptr;
            }
        }
    }

    std::set<std::string> required_permissions;
    collect_runtime_program_permissions(
        normalized,
        required_permissions);

    std::set<std::string> declared_permissions;
    const bool has_explicit_permissions =
        normalized.contains("permissions");
    if (has_explicit_permissions) {
        if (!normalized["permissions"].is_array()) {
            error = "manifest.permissions 必须是字符串数组";
            return false;
        }
        for (const auto& item : normalized["permissions"]) {
            if (!item.is_string()) {
                error = "manifest.permissions 必须是字符串数组";
                return false;
            }
            const std::string permission =
                item.get<std::string>();
            if (!runtime_program_known_permissions().count(
                    permission)) {
                error =
                    "未知 Runtime Program 权限: " + permission;
                return false;
            }
            declared_permissions.insert(permission);
        }

        std::vector<std::string> missing;
        for (const auto& required : required_permissions) {
            if (!declared_permissions.count(required))
                missing.push_back(required);
        }
        if (!missing.empty()) {
            std::ostringstream oss;
            oss << "manifest.permissions 少声明实际能力: ";
            for (size_t i = 0; i < missing.size(); ++i) {
                if (i) oss << ", ";
                oss << missing[i];
            }
            error = oss.str();
            return false;
        }
    } else {
        declared_permissions = required_permissions;
    }

    normalized["permissions"] =
        runtime_program_permission_array(declared_permissions);
    normalized["permissions_inferred"] =
        !has_explicit_permissions;

    if (normalized.dump().size() > (2u << 20)) {
        error = "manifest 过大（上限 2 MiB）";
        return false;
    }
    return true;
}

static std::string runtime_program_effective_target_id(
    const std::string& program_id,
    const std::string& local_id) {
    return "rp:" + program_id + ":" + local_id;
}

static json runtime_program_targets(const json& record) {
    json out = json::array();
    if (!record.value("enabled", false))
        return out;

    const std::string program_id = record.value("id", "");
    const int revision = record.value("revision", 0);
    const json manifest = record.value("manifest", json::object());

    for (const auto& source : manifest.value("targets", json::array())) {
        if (!source.is_object()) continue;
        json target = source;
        const std::string local_id = target.value("id", "");
        target["id"] =
            runtime_program_effective_target_id(program_id, local_id);
        target["__reconbridge_program"] = program_id;
        target["__reconbridge_local_id"] = local_id;
        target["__reconbridge_program_revision"] = revision;
        out.push_back(std::move(target));
    }

    const json state_init =
        manifest.value("state_init", json::array());
    if (state_init.is_array() && !state_init.empty()) {
        json actions = json::array();
        for (const auto& row : state_init) {
            if (!row.is_object()) continue;
            json action = {
                {"action", "set_state"},
                {"scope", row.value("scope", "process")},
                {"key", row.value("key", "")},
                {"value", row.contains("value") ? row["value"] : json(nullptr)}
            };
            actions.push_back(std::move(action));
        }

        json bootstrap = {
            {"kind", "runtime"},
            {"id", runtime_program_effective_target_id(
                program_id, "__bootstrap")},
            {"__reconbridge_program", program_id},
            {"__reconbridge_local_id", "__bootstrap"},
            {"__reconbridge_program_revision", revision},
            {"on_lifecycle", {
                {"stage", "application_attached"},
                {"actions", actions}
            }}
        };
        out.push_back(std::move(bootstrap));
    }

    return out;
}

static std::vector<json> load_runtime_program_records(
    const std::string& pkg) {
    std::vector<json> records;
    const std::string dir = runtime_program_package_dir(pkg);
    DIR* d = opendir(dir.c_str());
    if (!d) return records;

    std::vector<std::string> names;
    struct dirent* entry;
    while ((entry = readdir(d)) != nullptr) {
        std::string name = entry->d_name;
        if (name.size() <= 5 ||
            name.substr(name.size() - 5) != ".json")
            continue;
        names.push_back(std::move(name));
    }
    closedir(d);
    std::sort(names.begin(), names.end());

    for (const auto& name : names) {
        json record;
        if (read_json_file(dir + "/" + name, record) &&
            record.is_object()) {
            records.push_back(std::move(record));
        }
    }
    return records;
}

static json compose_hook_config_with_runtime_programs(
    const std::string& pkg,
    const json& base_config) {
    json result = base_config.is_object()
        ? base_config
        : json::object();
    result["package"] = pkg;
    result["restart"] = false;

    json targets = json::array();
    const json existing =
        result.value("targets", json::array());
    if (existing.is_array()) {
        for (const auto& target : existing) {
            if (!target.is_object()) continue;
            if (target.contains("__reconbridge_program"))
                continue;
            targets.push_back(target);
        }
    }

    for (const auto& record : load_runtime_program_records(pkg)) {
        if (!record.value("enabled", false))
            continue;
        const json manifest =
            record.value("manifest", json::object());
        const json evaluation =
            runtime_program_policy_evaluate(
                pkg,
                record.value("id", ""),
                manifest);
        if (evaluation.value(
                "decision",
                "deny") != "allow")
            continue;
        for (const auto& target : runtime_program_targets(record))
            targets.push_back(target);
    }
    result["targets"] = std::move(targets);
    return result;
}

static json runtime_program_materialize_locked(
    const std::string& pkg) {
    json base = json::object();
    (void)read_json_file(hook_path(pkg), base);
    json config =
        compose_hook_config_with_runtime_programs(pkg, base);

    ::mkdir(g_hooks_dir.c_str(), 0755);
    if (!write_json_atomic(hook_path(pkg), config)) {
        return {
            {"ok", false},
            {"error", "写入 materialized hook 配置失败"}
        };
    }

    const std::string payload = config.dump(2);
    const int hot = hot_reload(pkg, payload);
    size_t program_targets = 0;
    size_t manual_targets = 0;
    for (const auto& target :
         config.value("targets", json::array())) {
        if (target.is_object() &&
            target.contains("__reconbridge_program"))
            ++program_targets;
        else
            ++manual_targets;
    }

    return {
        {"ok", true},
        {"hot_injected", hot},
        {"manual_target_count", manual_targets},
        {"program_target_count", program_targets},
        {"total_target_count", manual_targets + program_targets}
    };
}

static json runtime_program_state_apply(
    const std::string& pkg,
    const json& rows,
    bool remove,
    int timeout_ms) {
    json results = json::array();
    if (!rows.is_array())
        return {{"attempted", 0}, {"results", results}};

    for (const auto& row : rows) {
        if (!row.is_object()) continue;
        json command = {
            {"op", remove ? "state_remove" : "state_set"},
            {"scope", row.value("scope", "process")},
            {"key", row.value("key", "")}
        };
        if (!remove) {
            command["value"] =
                row.contains("value") ? row["value"] : json(nullptr);
        }
        results.push_back(
            dispatch_runtime_command_internal(
                pkg,
                "",
                std::move(command),
                timeout_ms));
    }
    return {
        {"attempted", results.size()},
        {"results", results}
    };
}

static json runtime_program_record_summary(const json& record) {
    const json manifest =
        record.value("manifest", json::object());
    json effective_ids = json::array();
    for (const auto& target :
         manifest.value("targets", json::array())) {
        if (!target.is_object()) continue;
        effective_ids.push_back(
            runtime_program_effective_target_id(
                record.value("id", ""),
                target.value("id", "")));
    }
    if (!manifest.value("state_init", json::array()).empty()) {
        effective_ids.push_back(
            runtime_program_effective_target_id(
                record.value("id", ""),
                "__bootstrap"));
    }

    const std::string pkg =
        record.value("package", "");
    const json policy =
        runtime_program_policy_evaluate(
            pkg,
            record.value("id", ""),
            manifest);

    return {
        {"id", record.value("id", "")},
        {"package", pkg},
        {"revision", record.value("revision", 0)},
        {"enabled", record.value("enabled", false)},
        {"effective_enabled",
         record.value("enabled", false) &&
         policy.value("decision", "deny") == "allow"},
        {"policy", policy},
        {"name", manifest.value("name", record.value("id", ""))},
        {"version", manifest.value("version", "1")},
        {"description", manifest.value("description", "")},
        {"target_count", manifest.value("targets", json::array()).size()},
        {"state_init_count", manifest.value("state_init", json::array()).size()},
        {"state_cleanup_count", manifest.value("state_cleanup", json::array()).size()},
        {"permissions", manifest.value("permissions", json::array())},
        {"permissions_inferred", manifest.value("permissions_inferred", false)},
        {"history_depth", record.value("history", json::array()).size()},
        {"effective_target_ids", effective_ids},
        {"installed_at", record.value("installed_at", (int64_t)0)},
        {"updated_at", record.value("updated_at", (int64_t)0)},
        {"manifest", manifest}
    };
}

static void handle_runtime_program_install(
    const Request& req,
    Response& res) {
    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        reply(res, 400, {{"error", "body 非合法 JSON"}});
        return;
    }
    if (!body.is_object()) {
        reply(res, 400, {{"error", "body 必须是 JSON object"}});
        return;
    }

    const std::string pkg = body.value("package", "");
    if (!valid_pkg(pkg)) {
        reply(res, 400, {{"error", "invalid or missing package"}});
        return;
    }
    if (!body.contains("manifest") ||
        !body["manifest"].is_object()) {
        reply(res, 400, {{"error", "缺少 manifest object"}});
        return;
    }

    json manifest;
    std::string error;
    if (!normalize_runtime_program_manifest(
            body["manifest"], manifest, error)) {
        reply(res, 400, {{"error", error}});
        return;
    }

    const std::string id = manifest.value("id", "");
    const std::string mode = body.value("mode", "install");
    if (mode != "install" && mode != "replace") {
        reply(res, 400, {{"error", "mode 仅支持 install/replace"}});
        return;
    }

    const int timeout_ms = std::max(
        200,
        std::min(body.value("timeout_ms", 3000), 10000));
    const bool restart = body.value("restart", false);

    json old_record;
    json record;
    json materialized;
    bool had_old = false;
    {
        std::lock_guard<std::mutex> lk(g_program_mutex);
        const std::string pkg_dir =
            runtime_program_package_dir(pkg);
        ::mkdir(g_programs_dir.c_str(), 0755);
        ::mkdir(pkg_dir.c_str(), 0755);

        had_old = read_json_file(
            runtime_program_path(pkg, id),
            old_record);

        if (mode == "install" && had_old) {
            reply(res, 409, {{
                "error",
                "Runtime Program 已存在；请使用 replace"
            }});
            return;
        }
        if (mode == "replace" && !had_old) {
            reply(res, 404, {{
                "error",
                "Runtime Program 不存在；请先 install"
            }});
            return;
        }

        if (had_old && body.contains("expected_revision")) {
            const int expected =
                body.value("expected_revision", -1);
            if (expected != old_record.value("revision", 0)) {
                reply(res, 409, {
                    {"error", "revision 冲突"},
                    {"expected_revision", expected},
                    {"current_revision",
                     old_record.value("revision", 0)}
                });
                return;
            }
        }

        json history = had_old
            ? old_record.value("history", json::array())
            : json::array();
        if (!history.is_array())
            history = json::array();

        if (had_old) {
            history.push_back({
                {"revision", old_record.value("revision", 0)},
                {"enabled", old_record.value("enabled", false)},
                {"manifest", old_record.value(
                    "manifest", json::object())},
                {"updated_at", old_record.value(
                    "updated_at", (int64_t)0)}
            });
            while (history.size() > 5)
                history.erase(history.begin());
        }

        const bool enabled = body.contains("enable")
            ? body.value("enable", true)
            : (had_old
                ? old_record.value("enabled", true)
                : true);
        const int revision =
            had_old ? old_record.value("revision", 0) + 1 : 1;
        const int64_t timestamp = now_ms();

        record = {
            {"schema", 1},
            {"package", pkg},
            {"id", id},
            {"revision", revision},
            {"enabled", enabled},
            {"manifest", manifest},
            {"history", history},
            {"installed_at", had_old
                ? old_record.value("installed_at", timestamp)
                : timestamp},
            {"updated_at", timestamp}
        };

        if (!write_json_atomic(
                runtime_program_path(pkg, id),
                record)) {
            reply(res, 500, {{
                "error",
                "写入 Runtime Program 记录失败"
            }});
            return;
        }

        materialized =
            runtime_program_materialize_locked(pkg);
    }

    json cleanup = json::object();
    if (had_old &&
        old_record.value("enabled", false) &&
        !restart) {
        cleanup = runtime_program_state_apply(
            pkg,
            old_record.value("manifest", json::object())
                .value("state_cleanup", json::array()),
            true,
            timeout_ms);
    }

    json state_init = json::object();
    if (record.value("enabled", false) && !restart) {
        state_init = runtime_program_state_apply(
            pkg,
            manifest.value("state_init", json::array()),
            false,
            timeout_ms);
    }

    if (restart)
        run_detached({"am", "force-stop", pkg});

    reply(res, 200, {
        {"ok", materialized.value("ok", false)},
        {"mode", mode},
        {"program", runtime_program_record_summary(record)},
        {"materialized", materialized},
        {"state_cleanup", cleanup},
        {"state_init", state_init},
        {"restart_requested", restart},
        {"note", restart
            ? "Program 已持久化；目标下次启动会通过 bootstrap 自动初始化 State"
            : "Program 已持久化并尝试 live reconcile；在线进程同时应用 state_init"}
    });
}

static void handle_runtime_program_toggle(
    const Request& req,
    Response& res,
    bool enabled) {
    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        reply(res, 400, {{"error", "body 非合法 JSON"}});
        return;
    }

    const std::string pkg = body.value("package", "");
    const std::string id = body.value("id", "");
    if (!valid_pkg(pkg) || !valid_runtime_program_id(id)) {
        reply(res, 400, {{"error", "package 或 id 无效"}});
        return;
    }

    const int timeout_ms = std::max(
        200,
        std::min(body.value("timeout_ms", 3000), 10000));
    const bool restart = body.value("restart", false);

    json record;
    json materialized;
    {
        std::lock_guard<std::mutex> lk(g_program_mutex);
        if (!read_json_file(
                runtime_program_path(pkg, id),
                record)) {
            reply(res, 404, {{
                "error",
                "Runtime Program 不存在"
            }});
            return;
        }
        record["enabled"] = enabled;
        record["updated_at"] = now_ms();
        if (!write_json_atomic(
                runtime_program_path(pkg, id),
                record)) {
            reply(res, 500, {{
                "error",
                "写入 Runtime Program 状态失败"
            }});
            return;
        }
        materialized =
            runtime_program_materialize_locked(pkg);
    }

    json state_result = json::object();
    if (!restart) {
        const json manifest =
            record.value("manifest", json::object());
        state_result = runtime_program_state_apply(
            pkg,
            manifest.value(
                enabled ? "state_init" : "state_cleanup",
                json::array()),
            !enabled,
            timeout_ms);
    }
    if (restart)
        run_detached({"am", "force-stop", pkg});

    reply(res, 200, {
        {"ok", materialized.value("ok", false)},
        {"program", runtime_program_record_summary(record)},
        {"materialized", materialized},
        {enabled ? "state_init" : "state_cleanup",
         state_result},
        {"restart_requested", restart}
    });
}

static void handle_runtime_program_enable(
    const Request& req,
    Response& res) {
    handle_runtime_program_toggle(req, res, true);
}

static void handle_runtime_program_disable(
    const Request& req,
    Response& res) {
    handle_runtime_program_toggle(req, res, false);
}

static void handle_runtime_program_rollback(
    const Request& req,
    Response& res) {
    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        reply(res, 400, {{"error", "body 非合法 JSON"}});
        return;
    }

    const std::string pkg = body.value("package", "");
    const std::string id = body.value("id", "");
    if (!valid_pkg(pkg) || !valid_runtime_program_id(id)) {
        reply(res, 400, {{"error", "package 或 id 无效"}});
        return;
    }

    const int timeout_ms = std::max(
        200,
        std::min(body.value("timeout_ms", 3000), 10000));
    const bool restart = body.value("restart", false);

    json current;
    json restored;
    json materialized;
    int restored_from_revision = 0;
    {
        std::lock_guard<std::mutex> lk(g_program_mutex);
        if (!read_json_file(
                runtime_program_path(pkg, id),
                current)) {
            reply(res, 404, {{
                "error",
                "Runtime Program 不存在"
            }});
            return;
        }
        json history =
            current.value("history", json::array());
        if (!history.is_array() || history.empty()) {
            reply(res, 409, {{
                "error",
                "没有可回滚的历史版本"
            }});
            return;
        }

        const json previous = history.back();
        history.erase(history.end() - 1);
        restored_from_revision =
            previous.value("revision", 0);

        restored = current;
        restored["revision"] =
            current.value("revision", 0) + 1;
        restored["enabled"] =
            previous.value("enabled", true);
        restored["manifest"] =
            previous.value("manifest", json::object());
        restored["history"] = history;
        restored["updated_at"] = now_ms();
        restored["rollback_from_revision"] =
            current.value("revision", 0);
        restored["restored_from_revision"] =
            restored_from_revision;

        if (!write_json_atomic(
                runtime_program_path(pkg, id),
                restored)) {
            reply(res, 500, {{
                "error",
                "写入 rollback 结果失败"
            }});
            return;
        }
        materialized =
            runtime_program_materialize_locked(pkg);
    }

    json cleanup = json::object();
    json state_init = json::object();
    if (!restart) {
        if (current.value("enabled", false)) {
            cleanup = runtime_program_state_apply(
                pkg,
                current.value("manifest", json::object())
                    .value("state_cleanup", json::array()),
                true,
                timeout_ms);
        }
        if (restored.value("enabled", false)) {
            state_init = runtime_program_state_apply(
                pkg,
                restored.value("manifest", json::object())
                    .value("state_init", json::array()),
                false,
                timeout_ms);
        }
    }
    if (restart)
        run_detached({"am", "force-stop", pkg});

    reply(res, 200, {
        {"ok", materialized.value("ok", false)},
        {"program", runtime_program_record_summary(restored)},
        {"materialized", materialized},
        {"state_cleanup", cleanup},
        {"state_init", state_init},
        {"restored_from_revision", restored_from_revision},
        {"restart_requested", restart}
    });
}

static void handle_runtime_program_status(
    const Request& req,
    Response& res) {
    std::string pkg;
    std::string id;
    if (req.has_param("package"))
        pkg = req.get_param_value("package");
    if (req.has_param("id"))
        id = req.get_param_value("id");

    if (!valid_pkg(pkg)) {
        reply(res, 400, {{"error", "invalid or missing package"}});
        return;
    }
    if (!id.empty() && !valid_runtime_program_id(id)) {
        reply(res, 400, {{"error", "invalid program id"}});
        return;
    }

    std::lock_guard<std::mutex> lk(g_program_mutex);
    if (!id.empty()) {
        json record;
        if (!read_json_file(
                runtime_program_path(pkg, id),
                record)) {
            reply(res, 404, {{
                "error",
                "Runtime Program 不存在"
            }});
            return;
        }
        reply(res, 200, {
            {"count", 1},
            {"package", pkg},
            {"programs", json::array({
                runtime_program_record_summary(record)
            })}
        });
        return;
    }

    json programs = json::array();
    for (const auto& record :
         load_runtime_program_records(pkg)) {
        programs.push_back(
            runtime_program_record_summary(record));
    }
    reply(res, 200, {
        {"count", programs.size()},
        {"package", pkg},
        {"programs", programs}
    });
}

static void handle_hook(const Request& req, Response& res) {
    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        reply(res, 400, {{"error", "body 非合法 JSON"}});
        return;
    }
    if (!body.is_object()) {
        reply(res, 400, {{"error", "config/body 必须是 JSON 对象 (dict)，不能传字符串或标量"}});
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

    // mode:"append" —— 按 id 合并进现有配置（新的替换同 id，追加新 id），用于热加增量追加
    json to_write = body;
    std::string mode = body.value("mode", std::string("replace"));
    if (mode == "append") {
        std::ifstream in(hook_path(pkg));
        if (in.good()) {
            try {
                json existing;
                in >> existing;
                json merged = existing.value("targets", json::array());
                for (auto& nt : body["targets"]) {
                    std::string nid = nt.value("id", "");
                    bool replaced = false;
                    for (auto& et : merged)
                        if (et.value("id", "") == nid) { et = nt; replaced = true; break; }
                    if (!replaced) merged.push_back(nt);
                }
                to_write = existing;
                to_write["package"] = pkg;
                to_write["targets"] = merged;
                if (body.contains("debug")) to_write["debug"] = body["debug"];
            } catch (...) { /* 现有配置损坏则退回直接写 body */ }
        }
    }

    // 手工 Hook 与 Runtime Program 共用最终 materialized 配置。
    // 普通 /hook 只负责手工 targets；已启用 Program targets 始终由 Program manager 重建。
    {
        std::lock_guard<std::mutex> lk(g_program_mutex);
        to_write = compose_hook_config_with_runtime_programs(
            pkg,
            to_write);
        ::mkdir(g_hooks_dir.c_str(), 0755);
        if (!write_json_atomic(
                hook_path(pkg),
                to_write)) {
            reply(res, 500, {{"error", "写入 hook 配置失败"}});
            return;
        }
    }
    std::string written = to_write.dump(2);

    std::string note;
    int hot = 0;
    if (body.value("restart", false)) {
        run_detached({"am", "force-stop", pkg});
        note = "配置已写入，并已 force-stop 目标以触发重新注入";
    } else {
        // 免重启：向运行中的 tracer 下发“完整期望配置”，HookRegistry 会 reconcile add/remove/replace。
        hot = hot_reload(pkg, written);
        if (hot > 0)
            note = "配置已写入，并已实时同步到 " + std::to_string(hot) + " 个运行中进程";
        else
            note = "配置已写入；无运行中的 live reconcile 进程，将在目标下次启动时生效";
    }
    json installed = json::array();
    for (auto& t : body["targets"]) installed.push_back({{"id", t["id"]}});
    reply(res, 200, {{"ok", true}, {"package", pkg}, {"installed", installed},
                     {"hot_injected", hot}, {"note", note}});
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
    json desired = {
        {"package", pkg},
        {"restart", false},
        {"targets", json::array()}
    };
    bool config_existed = false;
    std::string removed_id;

    if (body.contains("id") && body["id"].is_string()) {
        removed_id = body["id"].get<std::string>();
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

        config_existed = true;
        json kept = json::array();
        for (auto& t : cfg.value("targets", json::array())) {
            if (!t.is_object()) continue;
            if (t.value("id", "") == removed_id &&
                t.contains("__reconbridge_program")) {
                reply(res, 409, {
                    {"error", "该 target 属于 Runtime Program；请使用 runtime_program_disable/replace"},
                    {"program_id", t.value("__reconbridge_program", "")},
                    {"target_id", removed_id}
                });
                return;
            }
            if (t.value("id", "") != removed_id)
                kept.push_back(t);
        }

        desired = cfg;
        desired["package"] = pkg;
        desired["restart"] = false;
        desired["targets"] = kept;
    } else {
        std::ifstream in(p);
        if (in.good()) {
            config_existed = true;
            try {
                json cfg;
                in >> cfg;
                desired = cfg;
            } catch (...) {
                desired = {
                    {"package", pkg},
                    {"restart", false},
                    {"targets", json::array()}
                };
            }
        }

        // 清空所有手工 target；Program target 会在 compose 阶段重新加入。
        desired["package"] = pkg;
        desired["restart"] = false;
        desired["targets"] = json::array();
    }

    {
        std::lock_guard<std::mutex> lk(g_program_mutex);
        desired = compose_hook_config_with_runtime_programs(
            pkg,
            desired);
        const bool has_program_records =
            !load_runtime_program_records(pkg).empty();
        const bool has_targets =
            !desired.value("targets", json::array()).empty();

        if (!has_program_records && !has_targets) {
            ::remove(p.c_str());
        } else if (!write_json_atomic(p, desired)) {
            reply(res, 500, {{"error", "写入 unhook 后配置失败"}});
            return;
        }
    }

    // 手工 Hook 被移除后，仍向在线 Tracer 下发包含 Program targets 的完整期望状态。
    int hot = hot_reload(pkg, desired.dump());
    std::string note;
    if (hot > 0)
        note = "手工 Hook 已移除，并已向 " + std::to_string(hot) +
               " 个运行中进程同步；已启用 Runtime Program 保持生效";
    else
        note = "手工 Hook 已移除；Runtime Program 记录保持不变";

    json result = {
        {"ok", true},
        {"package", pkg},
        {"removed", config_existed},
        {"hot_unhooked", hot},
        {"note", note}
    };
    if (!removed_id.empty())
        result["removed_id"] = removed_id;
    reply(res, 200, result);
}

static void handle_runtime_command(const Request& req, Response& res) {
    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        reply(res, 400, {{"error", "body 非合法 JSON"}});
        return;
    }
    if (!body.is_object()) {
        reply(res, 400, {{"error", "body 必须是 JSON object"}});
        return;
    }

    const std::string pkg = body.value("package", "");
    if (!valid_pkg(pkg)) {
        reply(res, 400, {{"error", "invalid or missing package"}});
        return;
    }

    const std::string process = body.value("process", "");
    int timeout_ms = body.value("timeout_ms", 3000);
    if (timeout_ms < 200) timeout_ms = 200;
    if (timeout_ms > 10000) timeout_ms = 10000;

    json command;
    if (body.contains("command") && body["command"].is_object()) {
        command = body["command"];
    } else {
        command = body;
        command.erase("package");
        command.erase("process");
        command.erase("timeout_ms");
    }

    if (!command.is_object() ||
        !command.contains("op") ||
        !command["op"].is_string() ||
        command["op"].get<std::string>().empty()) {
        reply(res, 400, {{"error", "Runtime command 缺少 op"}});
        return;
    }

    // 只给 Tracer 内部调度使用；Activity Action 据此控制主线程同步等待上限。
    command["_timeout_ms"] = timeout_ms;

    std::vector<std::shared_ptr<InjectConn>> targets;
    {
        std::lock_guard<std::mutex> lk(g_conn_mutex);
        for (const auto& conn : g_conns) {
            if (conn->base_pkg != pkg || !conn->command_capable)
                continue;
            if (!process.empty() && conn->process_name != process)
                continue;
            targets.push_back(conn);
        }
    }

    if (targets.empty()) {
        reply(res, 404, {
            {"ok", false},
            {"package", pkg},
            {"process", process.empty() ? json(nullptr) : json(process)},
            {"error", "没有在线且支持 Runtime Command 的 Tracer 进程"},
            {"runtime_status", runtime_status_snapshot(pkg)}
        });
        return;
    }

    std::vector<std::future<json>> futures;
    futures.reserve(targets.size());
    for (const auto& conn : targets) {
        futures.push_back(std::async(
            std::launch::async,
            [conn, command, timeout_ms]() mutable {
                return send_runtime_command_to_conn(
                    conn,
                    command,
                    timeout_ms);
            }));
    }

    json results = json::array();
    size_t succeeded = 0;
    for (auto& future : futures) {
        json result;
        try {
            result = future.get();
        } catch (const std::exception& e) {
            result = {
                {"ok", false},
                {"error", e.what()}
            };
        } catch (...) {
            result = {
                {"ok", false},
                {"error", "Runtime Command 未知异常"}
            };
        }
        if (result.value("ok", false))
            ++succeeded;
        results.push_back(std::move(result));
    }

    reply(res, 200, {
        {"ok", succeeded > 0},
        {"package", pkg},
        {"process", process.empty() ? json(nullptr) : json(process)},
        {"targeted", targets.size()},
        {"succeeded", succeeded},
        {"op", command.value("op", "")},
        {"results", results}
    });
}

static void handle_runtime_status(const Request& req, Response& res) {
    std::string pkg;
    if (req.has_param("package"))
        pkg = req.get_param_value("package");
    if (!pkg.empty() && !valid_pkg(pkg)) {
        reply(res, 400, {{"error", "invalid package"}});
        return;
    }
    reply(res, 200, runtime_status_snapshot(pkg));
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

// GET /recent —— 事后采集：返回环形缓冲里最近的事件（P0-1）。
// query: limit（默认 200，最多返回条数；0 只取游标）、since_seq（只返回该游标之后的）。
// 返回 {latest_seq, count, events:[...]}；latest_seq 可作为下次的 since_seq 游标。
static void handle_recent(const Request& req, Response& res) {
    uint64_t since = 0;
    size_t limit = 200;
    if (req.has_param("since_seq"))
        since = strtoull(req.get_param_value("since_seq").c_str(), nullptr, 10);
    if (req.has_param("limit")) {
        long l = strtol(req.get_param_value("limit").c_str(), nullptr, 10);
        if (l >= 0) limit = (size_t)l;
    }
    auto items = g_broadcaster.recent(since, limit);
    json arr = json::array();
    for (auto& it : items) {
        try {
            arr.push_back(json::parse(it.second));  // 事件本是 JSON，尽量以对象返回
        } catch (...) {
            arr.push_back(it.second);               // 解析失败原样字符串
        }
    }
    reply(res, 200, {{"latest_seq", g_broadcaster.latest_seq()},
                     {"count", arr.size()}, {"events", arr}});
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
    svr.Get("/runtime_status", handle_runtime_status);
    svr.Post("/runtime_command", handle_runtime_command);
    svr.Post("/runtime_program/install", handle_runtime_program_install);
    svr.Post("/runtime_program/enable", handle_runtime_program_enable);
    svr.Post("/runtime_program/disable", handle_runtime_program_disable);
    svr.Post("/runtime_program/rollback", handle_runtime_program_rollback);
    svr.Get("/runtime_programs", handle_runtime_program_status);
    svr.Post("/dump_dex", handle_dump_dex);
    svr.Get("/dumps", handle_dumps);
    svr.Get("/events", handle_events_sse);  // SSE
    svr.Get("/recent", handle_recent);      // 事后采集环形缓冲
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
    g_programs_dir = base_dir + "/runtime_programs";
    g_program_policy_dir =
        base_dir + "/runtime_program_policies";
    ::mkdir(g_hooks_dir.c_str(), 0755);
    ::mkdir(g_dumps_dir.c_str(), 0755);
    ::mkdir(g_programs_dir.c_str(), 0755);
    ::mkdir(g_program_policy_dir.c_str(), 0755);
    // 确保 events.log 存在（保留旧的 file-tail 兜底路径）
    { std::ofstream f(g_events_log, std::ios::app); }
    std::thread(events_watcher).detach();
    // 注入 IPC 抽象 socket（注入层直连守护进程取配置/回传事件）
    std::thread(inject_server).detach();
}

}  // namespace dynamic

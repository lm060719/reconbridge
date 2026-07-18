// ReconBridge M1 静态传输层守护进程
// 职责：在 KernelSU root 环境下提供局域网 HTTP 原子能力接口（拉包 / 读文件 / 列 so / procfs / 白名单 shell）。
// 设计要点：
//   - 端口默认关闭，读 config.conf 决定是否监听；inotify 监听配置变更即时生效。
//   - 所有接口 token 鉴权；token 启动时随机生成写入配置。
//   - 大文件流式传输，不一次性读进内存。
//   - 本守护进程只做搬运，不含任何特定 App 逻辑。

#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "third_party/httplib.h"
#include "third_party/json.hpp"
#include "dynamic.h"

using json = nlohmann::json;
using namespace httplib;

// ---------------------------------------------------------------------------
// 全局常量 / 状态
// ---------------------------------------------------------------------------
static const char* kName = "ReconBridge";
static const char* kVersion = "M1.0";

static std::string g_config_path = "/data/adb/reconbridge/config.conf";
static std::string g_log_path = "/data/adb/reconbridge/daemon.log";
static time_t g_start_time = 0;

struct Config {
    bool enabled = false;
    int port = 8787;
    std::string bind = "auto";  // auto = 自动探测 wlan0 IP，否则用具体 IP
    std::string token;
};

static std::mutex g_mtx;                     // 保护服务器生命周期
static Config g_config;                       // 当前配置
static std::unique_ptr<httplib::Server> g_svr;
static std::thread g_svr_thread;
static bool g_running = false;                // 当前是否在监听

// ---------------------------------------------------------------------------
// 日志
// ---------------------------------------------------------------------------
static void log_line(const std::string& msg) {
    char ts[32];
    time_t t = time(nullptr);
    struct tm tmv;
    localtime_r(&t, &tmv);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tmv);
    std::string line = std::string("[") + ts + "] " + msg + "\n";
    fputs(line.c_str(), stderr);
    std::ofstream f(g_log_path, std::ios::app);
    if (f.good()) f << line;
}

// ---------------------------------------------------------------------------
// 工具函数
// ---------------------------------------------------------------------------
static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

static std::string basename_of(const std::string& p) {
    size_t pos = p.find_last_of('/');
    return pos == std::string::npos ? p : p.substr(pos + 1);
}

static std::string dirname_of(const std::string& p) {
    size_t pos = p.find_last_of('/');
    return pos == std::string::npos ? "." : p.substr(0, pos);
}

// 生成随机 hex token
static std::string gen_token(size_t bytes = 16) {
    std::string out;
    std::ifstream f("/dev/urandom", std::ios::binary);
    static const char* hex = "0123456789abcdef";
    for (size_t i = 0; i < bytes; i++) {
        unsigned char c = 0;
        f.read(reinterpret_cast<char*>(&c), 1);
        out.push_back(hex[c >> 4]);
        out.push_back(hex[c & 0xF]);
    }
    return out;
}

// 包名合法性校验（防止把奇怪字符塞进 pm argv）
static bool valid_pkg(const std::string& s) {
    if (s.empty() || s.size() > 256) return false;
    for (char c : s) {
        if (!(isalnum((unsigned char)c) || c == '.' || c == '_')) return false;
    }
    return true;
}

// 探测 wlan0 的 IPv4 地址，找不到返回空
static std::string wlan_ip() {
    struct ifaddrs* ifap = nullptr;
    if (getifaddrs(&ifap) != 0) return "";
    std::string result;
    for (struct ifaddrs* i = ifap; i; i = i->ifa_next) {
        if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET) continue;
        std::string name = i->ifa_name ? i->ifa_name : "";
        if (name.rfind("wlan", 0) != 0) continue;  // wlan0 / wlan1...
        char buf[INET_ADDRSTRLEN] = {0};
        auto* sa = reinterpret_cast<struct sockaddr_in*>(i->ifa_addr);
        inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf));
        result = buf;
        break;
    }
    freeifaddrs(ifap);
    return result;
}

// ---------------------------------------------------------------------------
// 执行子进程并捕获 stdout/stderr（不经过 sh -c，避免注入）
// ---------------------------------------------------------------------------
struct ExecResult {
    int rc = -1;
    std::string out;
    std::string err;
    bool timed_out = false;
};

static ExecResult exec_capture(const std::vector<std::string>& argv, int timeout_ms = 20000) {
    ExecResult r;
    if (argv.empty()) return r;

    int outp[2], errp[2];
    if (pipe(outp) != 0 || pipe(errp) != 0) {
        r.err = "pipe failed";
        return r;
    }

    pid_t pid = fork();
    if (pid < 0) {
        r.err = "fork failed";
        return r;
    }
    if (pid == 0) {
        // 子进程
        dup2(outp[1], STDOUT_FILENO);
        dup2(errp[1], STDERR_FILENO);
        close(outp[0]); close(outp[1]);
        close(errp[0]); close(errp[1]);
        std::vector<char*> cargv;
        for (auto& a : argv) cargv.push_back(const_cast<char*>(a.c_str()));
        cargv.push_back(nullptr);
        execvp(cargv[0], cargv.data());
        // execvp 失败
        fprintf(stderr, "exec failed: %s\n", strerror(errno));
        _exit(127);
    }

    // 父进程
    close(outp[1]);
    close(errp[1]);
    fcntl(outp[0], F_SETFL, O_NONBLOCK);
    fcntl(errp[0], F_SETFL, O_NONBLOCK);

    struct pollfd fds[2];
    fds[0].fd = outp[0]; fds[0].events = POLLIN;
    fds[1].fd = errp[0]; fds[1].events = POLLIN;
    int open_cnt = 2;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);

    while (open_cnt > 0) {
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            r.timed_out = true;
            kill(pid, SIGKILL);
            break;
        }
        int wait_ms = (int)std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        int n = poll(fds, 2, std::min(wait_ms, 1000));
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        for (int k = 0; k < 2; k++) {
            if (fds[k].fd < 0) continue;
            if (fds[k].revents & (POLLIN | POLLHUP)) {
                char buf[8192];
                ssize_t got = read(fds[k].fd, buf, sizeof(buf));
                if (got > 0) {
                    (k == 0 ? r.out : r.err).append(buf, got);
                } else if (got == 0) {
                    close(fds[k].fd);
                    fds[k].fd = -1;
                    open_cnt--;
                }
            }
        }
    }

    if (outp[0] >= 0) close(outp[0]);
    if (errp[0] >= 0) close(errp[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) r.rc = WEXITSTATUS(status);
    else r.rc = -1;
    return r;
}

// ---------------------------------------------------------------------------
// 配置读写（简单 key=value 文本，便于 WebUI/shell 直接编辑）
// ---------------------------------------------------------------------------
static Config load_config(const std::string& path) {
    Config c;
    std::ifstream f(path);
    std::string line;
    while (std::getline(f, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = trim(line.substr(0, eq));
        std::string v = trim(line.substr(eq + 1));
        if (k == "enabled") c.enabled = (v == "1" || v == "true");
        else if (k == "port") c.port = atoi(v.c_str());
        else if (k == "bind") c.bind = v;
        else if (k == "token") c.token = v;
    }
    return c;
}

static void save_config(const std::string& path, const Config& c) {
    std::ofstream f(path, std::ios::trunc);
    f << "# ReconBridge 配置（key=value）。enabled=1 开启端口，enabled=0 关闭。\n";
    f << "enabled=" << (c.enabled ? 1 : 0) << "\n";
    f << "port=" << c.port << "\n";
    f << "bind=" << c.bind << "\n";
    f << "token=" << c.token << "\n";
}

// ---------------------------------------------------------------------------
// 鉴权
// ---------------------------------------------------------------------------
static bool authed(const Request& req) {
    std::string tok;
    if (req.has_header("X-Token")) tok = req.get_header_value("X-Token");
    if (tok.empty() && req.has_header("Authorization")) {
        std::string a = req.get_header_value("Authorization");
        const std::string p = "Bearer ";
        if (a.rfind(p, 0) == 0) tok = a.substr(p.size());
    }
    if (tok.empty() && req.has_param("token")) tok = req.get_param_value("token");
    if (tok.empty() || g_config.token.empty()) return false;
    // 长度先比，再逐字节，避免明显短路
    if (tok.size() != g_config.token.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < tok.size(); i++) diff |= (unsigned char)(tok[i] ^ g_config.token[i]);
    return diff == 0;
}

static void json_reply(Response& res, int status, const json& j) {
    res.status = status;
    res.set_content(j.dump(2), "application/json; charset=utf-8");
}

// 流式返回文件；download_name 为下载文件名
static void stream_file(Response& res, const std::string& path, const std::string& download_name) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) {
        json_reply(res, 404, {{"error", "file not found"}, {"path", path}});
        return;
    }
    auto fp = std::make_shared<std::ifstream>(path, std::ios::binary);
    if (!fp->good()) {
        json_reply(res, 500, {{"error", "cannot open file"}, {"path", path}});
        return;
    }
    size_t size = (size_t)st.st_size;
    res.set_header("Content-Disposition",
                   "attachment; filename=\"" + download_name + "\"");
    res.set_content_provider(
        size, "application/octet-stream",
        [fp](size_t offset, size_t length, DataSink& sink) -> bool {
            char buf[65536];
            fp->clear();  // 清掉可能残留的 eof/fail 位
            fp->seekg((std::streamoff)offset);
            size_t to_read = std::min(length, sizeof(buf));
            fp->read(buf, (std::streamsize)to_read);
            std::streamsize n = fp->gcount();
            // 读不到数据（文件被截断/异常）直接中止，避免 httplib 因 offset 不前进而死循环
            if (n <= 0) return false;
            return sink.write(buf, (size_t)n);
        },
        [fp](bool) { /* releaser：fp 随 shared_ptr 释放 */ });
}

// ---------------------------------------------------------------------------
// 路由处理
// ---------------------------------------------------------------------------

// pm path <pkg> → 全部 apk 路径
static std::vector<std::string> apk_paths(const std::string& pkg) {
    std::vector<std::string> paths;
    ExecResult r = exec_capture({"pm", "path", pkg});
    std::istringstream is(r.out);
    std::string line;
    while (std::getline(is, line)) {
        line = trim(line);
        const std::string pfx = "package:";
        if (line.rfind(pfx, 0) == 0) paths.push_back(line.substr(pfx.size()));
    }
    return paths;
}

static void handle_packages(const Request&, Response& res) {
    // 系统应用集合
    std::set<std::string> sys;
    {
        ExecResult r = exec_capture({"pm", "list", "packages", "-s"});
        std::istringstream is(r.out);
        std::string line;
        while (std::getline(is, line)) {
            line = trim(line);
            const std::string pfx = "package:";
            if (line.rfind(pfx, 0) == 0) sys.insert(line.substr(pfx.size()));
        }
    }
    // 路径 + versionCode
    ExecResult r = exec_capture({"pm", "list", "packages", "-f", "--show-versioncode"});
    json arr = json::array();
    std::istringstream is(r.out);
    std::string line;
    while (std::getline(is, line)) {
        line = trim(line);
        const std::string pfx = "package:";
        if (line.rfind(pfx, 0) != 0) continue;
        std::string s = line.substr(pfx.size());
        std::string vc;
        size_t vpos = s.find(" versionCode:");
        if (vpos != std::string::npos) {
            vc = s.substr(vpos + std::string(" versionCode:").size());
            s = s.substr(0, vpos);
        }
        size_t eq = s.rfind('=');
        if (eq == std::string::npos) continue;
        std::string path = s.substr(0, eq);
        std::string pkg = s.substr(eq + 1);
        arr.push_back({{"package", pkg},
                       {"path", path},
                       {"versionCode", vc},
                       {"system", sys.count(pkg) > 0}});
    }
    json_reply(res, 200, {{"count", arr.size()}, {"packages", arr}});
}

static void handle_apk(const Request& req, Response& res) {
    std::string pkg = req.get_param_value("pkg");
    if (!valid_pkg(pkg)) {
        json_reply(res, 400, {{"error", "invalid or missing pkg"}});
        return;
    }
    auto paths = apk_paths(pkg);
    if (paths.empty()) {
        json_reply(res, 404, {{"error", "package not found or no apk"}, {"pkg", pkg}});
        return;
    }
    // 指定 path 则下载单个（必须在该包的 apk 列表内）
    if (req.has_param("path")) {
        std::string want = req.get_param_value("path");
        if (std::find(paths.begin(), paths.end(), want) == paths.end()) {
            json_reply(res, 403, {{"error", "path not belong to package"}, {"pkg", pkg}});
            return;
        }
        stream_file(res, want, basename_of(want));
        return;
    }
    // 否则返回全部 apk 路径 + 大小
    json arr = json::array();
    for (auto& p : paths) {
        struct stat st;
        long size = (stat(p.c_str(), &st) == 0) ? (long)st.st_size : -1;
        arr.push_back({{"path", p}, {"name", basename_of(p)}, {"size", size}});
    }
    json_reply(res, 200, {{"package", pkg}, {"count", arr.size()}, {"apks", arr}});
}

static void handle_file(const Request& req, Response& res) {
    std::string path = req.get_param_value("path");
    if (path.empty() || path[0] != '/') {
        json_reply(res, 400, {{"error", "path must be absolute"}});
        return;
    }
    stream_file(res, path, basename_of(path));
}

// 递归收集 dir 下的 .so
static void collect_so(const std::string& dir, std::vector<std::string>& out) {
    // 用 ls -R 太脆；用 find（白名单命令内），失败则退回单层
    ExecResult r = exec_capture({"find", dir, "-name", "*.so", "-type", "f"});
    if (r.rc == 0) {
        std::istringstream is(r.out);
        std::string line;
        while (std::getline(is, line)) {
            line = trim(line);
            if (!line.empty()) out.push_back(line);
        }
    }
}

static void handle_libs(const Request& req, Response& res) {
    std::string pkg = req.get_param_value("pkg");
    if (!valid_pkg(pkg)) {
        json_reply(res, 400, {{"error", "invalid or missing pkg"}});
        return;
    }
    auto paths = apk_paths(pkg);
    if (paths.empty()) {
        json_reply(res, 404, {{"error", "package not found"}, {"pkg", pkg}});
        return;
    }
    // apk 所在目录的 lib/ 子目录（extractNativeLibs=true 时才有落地 so）
    std::string apkdir = dirname_of(paths[0]);
    std::string libdir = apkdir + "/lib";
    std::vector<std::string> sos;
    collect_so(libdir, sos);

    if (req.has_param("path")) {
        std::string want = req.get_param_value("path");
        if (std::find(sos.begin(), sos.end(), want) == sos.end()) {
            json_reply(res, 403, {{"error", "so not belong to package lib dir"}, {"pkg", pkg}});
            return;
        }
        stream_file(res, want, basename_of(want));
        return;
    }

    json arr = json::array();
    for (auto& p : sos) {
        struct stat st;
        long size = (stat(p.c_str(), &st) == 0) ? (long)st.st_size : -1;
        arr.push_back({{"path", p}, {"name", basename_of(p)}, {"size", size}});
    }
    json note = arr.empty()
        ? json("lib 目录无落地 .so，可能 extractNativeLibs=false，so 在 apk 内 lib/arm64-v8a/，请用 /apk 拉 apk 后本地解包")
        : json();
    json_reply(res, 200, {{"package", pkg}, {"libdir", libdir},
                          {"count", arr.size()}, {"libs", arr}, {"note", note}});
}

static void handle_proc(const Request& req, Response& res) {
    std::string pid = req.get_param_value("pid");
    std::string what = req.get_param_value("what");
    if (pid.empty() || !std::all_of(pid.begin(), pid.end(), ::isdigit)) {
        json_reply(res, 400, {{"error", "invalid pid"}});
        return;
    }
    static const std::set<std::string> allowed = {"maps", "status", "cmdline"};
    if (!allowed.count(what)) {
        json_reply(res, 400, {{"error", "what must be maps|status|cmdline"}});
        return;
    }
    std::string path = "/proc/" + pid + "/" + what;
    std::ifstream f(path, std::ios::binary);
    if (!f.good()) {
        json_reply(res, 404, {{"error", "cannot read"}, {"path", path}});
        return;
    }
    std::stringstream ss;
    ss << f.rdbuf();
    std::string content = ss.str();
    // cmdline 以 \0 分隔，替换成空格便于阅读
    if (what == "cmdline") {
        std::replace(content.begin(), content.end(), '\0', ' ');
    }
    res.set_content(content, "text/plain; charset=utf-8");
}

// /shell 白名单
static const std::set<std::string>& shell_whitelist() {
    static const std::set<std::string> wl = {
        "id", "whoami", "getprop", "uname", "ls", "cat", "stat", "du", "df",
        "md5sum", "sha1sum", "sha256sum", "pm", "cmd", "dumpsys", "ps",
        "getenforce", "settings", "wc", "head", "tail", "ip", "netstat",
        "pgrep", "mount", "readlink", "basename", "dirname", "find", "date"};
    return wl;
}

static void handle_shell(const Request& req, Response& res) {
    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        json_reply(res, 400, {{"error", "body must be JSON: {\"argv\":[...]} or {\"cmd\":\"...\"}"}});
        return;
    }
    std::vector<std::string> argv;
    if (body.contains("argv") && body["argv"].is_array()) {
        for (auto& e : body["argv"]) argv.push_back(e.get<std::string>());
    } else if (body.contains("cmd") && body["cmd"].is_string()) {
        // 朴素按空白切分（不支持引号，复杂命令请用 argv 形式）
        std::istringstream is(body["cmd"].get<std::string>());
        std::string tok;
        while (is >> tok) argv.push_back(tok);
    }
    if (argv.empty()) {
        json_reply(res, 400, {{"error", "empty command"}});
        return;
    }
    std::string prog = basename_of(argv[0]);
    if (!shell_whitelist().count(prog)) {
        json_reply(res, 403, {{"error", "command not in whitelist"}, {"program", prog}});
        return;
    }
    ExecResult r = exec_capture(argv);
    json_reply(res, r.timed_out ? 504 : 200,
               {{"program", prog}, {"rc", r.rc}, {"timed_out", r.timed_out},
                {"stdout", r.out}, {"stderr", r.err}});
}

// ---------------------------------------------------------------------------
// 服务器生命周期
// ---------------------------------------------------------------------------
static void register_routes(httplib::Server& svr) {
    // 全局鉴权
    svr.set_pre_routing_handler([](const Request& req, Response& res) {
        if (!authed(req)) {
            json_reply(res, 401, {{"error", "unauthorized"}, {"hint", "need X-Token / Authorization: Bearer / ?token="}});
            return Server::HandlerResponse::Handled;
        }
        return Server::HandlerResponse::Unhandled;
    });

    svr.Get("/health", [](const Request&, Response& res) {
        json_reply(res, 200, {{"status", "ok"}, {"name", kName}, {"version", kVersion},
                              {"pid", getpid()}, {"uptime_sec", (long)(time(nullptr) - g_start_time)}});
    });
    svr.Get("/packages", handle_packages);
    svr.Get("/apk", handle_apk);
    svr.Get("/file", handle_file);
    svr.Get("/libs", handle_libs);
    svr.Get("/proc", handle_proc);
    svr.Post("/shell", handle_shell);

    // M3 动态接口：/hook /unhook /hooks /events(SSE)
    dynamic::register_routes(svr);

    svr.set_payload_max_length(4 * 1024 * 1024);
}

static void start_server_locked() {
    if (g_running) return;
    std::string host = g_config.bind;
    if (host == "auto" || host.empty()) {
        std::string ip = wlan_ip();
        host = ip.empty() ? "0.0.0.0" : ip;
        if (ip.empty())
            log_line("警告：未探测到 wlan0 IP，回退绑定 0.0.0.0");
    }
    int port = g_config.port;
    g_svr = std::make_unique<httplib::Server>();
    register_routes(*g_svr);
    g_running = true;
    std::string bind_host = host;
    g_svr_thread = std::thread([bind_host, port]() {
        log_line("HTTP 服务启动，监听 " + bind_host + ":" + std::to_string(port));
        if (!g_svr->listen(bind_host.c_str(), port)) {
            log_line("错误：listen 失败 " + bind_host + ":" + std::to_string(port));
        }
        log_line("HTTP 服务已停止");
    });
    // M3：在 http 端口+1 起 WS 事件服务
    dynamic::on_server_start(bind_host, port);
}

static void stop_server_locked() {
    if (!g_running) return;
    dynamic::on_server_stop();  // M3：先停 WS 服务
    if (g_svr) g_svr->stop();
    if (g_svr_thread.joinable()) g_svr_thread.join();
    g_svr.reset();
    g_running = false;
}

static void apply_config(const Config& nc) {
    std::lock_guard<std::mutex> lk(g_mtx);
    bool need_restart = g_running &&
                        (nc.port != g_config.port || nc.bind != g_config.bind);
    g_config = nc;
    if (!nc.enabled) {
        if (g_running) {
            log_line("配置 enabled=0，关闭端口");
            stop_server_locked();
        }
        return;
    }
    // enabled=1
    if (g_running && need_restart) {
        log_line("端口/绑定变更，重启监听");
        stop_server_locked();
    }
    if (!g_running) {
        start_server_locked();
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc > 1) g_config_path = argv[1];
    g_start_time = time(nullptr);

    // 确保 PATH 能找到 pm/cmd/find 等
    setenv("PATH", "/system/bin:/system/xbin:/vendor/bin:/product/bin", 1);

    std::string dir = dirname_of(g_config_path);
    g_log_path = dir + "/daemon.log";

    // 加载或初始化配置
    Config cfg = load_config(g_config_path);
    bool changed = false;
    if (cfg.token.empty()) {
        cfg.token = gen_token();
        changed = true;
        log_line("首次启动，生成随机 token");
    }
    if (cfg.port <= 0 || cfg.port > 65535) { cfg.port = 8787; changed = true; }
    if (cfg.bind.empty()) { cfg.bind = "auto"; changed = true; }
    if (changed) save_config(g_config_path, cfg);

    log_line(std::string(kName) + " " + kVersion + " 启动，配置=" + g_config_path +
             " enabled=" + (cfg.enabled ? "1" : "0") + " port=" + std::to_string(cfg.port));

    // M3 动态子系统初始化（hooks 目录 + events.log 监听）
    dynamic::init(dir);

    apply_config(cfg);

    // inotify 监听配置目录，捕获 config.conf 变更
    int ifd = inotify_init1(IN_CLOEXEC);
    if (ifd < 0) {
        log_line("警告：inotify_init 失败，配置热更新不可用");
        // 退回：仅保持当前状态常驻
        while (true) sleep(3600);
    }
    inotify_add_watch(ifd, dir.c_str(),
                      IN_CLOSE_WRITE | IN_MOVED_TO | IN_MODIFY | IN_CREATE);
    std::string cfg_name = basename_of(g_config_path);

    char buf[4096];
    while (true) {
        ssize_t len = read(ifd, buf, sizeof(buf));
        if (len <= 0) {
            if (errno == EINTR) continue;
            break;
        }
        bool hit = false;
        for (char* p = buf; p < buf + len;) {
            auto* ev = reinterpret_cast<struct inotify_event*>(p);
            if (ev->len > 0) {
                std::string name(ev->name);
                if (name == cfg_name) hit = true;
            }
            p += sizeof(struct inotify_event) + ev->len;
        }
        if (hit) {
            // 简单防抖，等待写入完成
            std::this_thread::sleep_for(std::chrono::milliseconds(120));
            Config nc = load_config(g_config_path);
            if (nc.token.empty()) nc.token = g_config.token;  // 不丢 token
            log_line("检测到配置变更，enabled=" + std::string(nc.enabled ? "1" : "0"));
            apply_config(nc);
        }
    }
    return 0;
}

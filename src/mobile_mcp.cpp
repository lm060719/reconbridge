#include "mobile_mcp.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <thread>
#include <vector>

#include "third_party/json.hpp"

using json = nlohmann::json;
using namespace httplib;

namespace mobile_mcp {
namespace {

struct Context {
    std::string base_dir;
    std::string work_dir;
    std::string token;
    int public_port = 8790;
    int internal_port = 0;
};

static Context g_ctx;
static std::mutex g_sessions_mtx;
static std::set<std::string> g_sessions;

struct Artifact {
    std::string path;
    std::string name;
    std::string token;
    uint64_t bytes = 0;
    std::time_t modified = 0;
    std::time_t expires = 0;
};

static constexpr std::time_t kArtifactTtlSeconds = 30 * 60;
static constexpr size_t kMaxArtifacts = 512;
static std::mutex g_artifacts_mtx;
static std::map<std::string, Artifact> g_artifacts;

static std::string random_hex(size_t bytes = 16) {
    std::ifstream f("/dev/urandom", std::ios::binary);
    static const char* hex = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < bytes; ++i) {
        unsigned char c = 0;
        f.read(reinterpret_cast<char*>(&c), 1);
        out.push_back(hex[c >> 4]);
        out.push_back(hex[c & 15]);
    }
    return out;
}

static std::string basename_of(const std::string& path) {
    auto p = path.find_last_of('/');
    return p == std::string::npos ? path : path.substr(p + 1);
}

static std::string safe_name(const std::string& value, size_t max_len = 128) {
    std::string out;
    for (char c : value) {
        if (isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '-') out.push_back(c);
        else out.push_back('_');
        if (out.size() >= max_len) break;
    }
    return out.empty() ? "item" : out;
}

static bool valid_package(const std::string& value) {
    if (value.empty() || value.size() > 256) return false;
    for (char c : value)
        if (!(isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_')) return false;
    return true;
}

static bool constant_time_equal(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i) diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    return diff == 0;
}

static bool path_within(const std::filesystem::path& path,
                        const std::filesystem::path& root) {
    auto pit = path.begin();
    auto rit = root.begin();
    for (; rit != root.end(); ++rit, ++pit) {
        if (pit == path.end() || *pit != *rit) return false;
    }
    return true;
}

static bool allowed_artifact_path(const std::string& raw_path, std::string& canonical) {
    try {
        auto path = std::filesystem::canonical(raw_path);
        if (!std::filesystem::is_regular_file(path)) return false;
        auto work = std::filesystem::canonical(g_ctx.work_dir);
        auto dumps_dir = std::filesystem::path(g_ctx.base_dir) / "dumps";
        bool allowed = path_within(path, work);
        if (!allowed && std::filesystem::exists(dumps_dir)) {
            allowed = path_within(path, std::filesystem::canonical(dumps_dir));
        }
        if (!allowed) return false;
        canonical = path.string();
        return true;
    } catch (...) {
        return false;
    }
}

static void prune_artifacts_locked(std::time_t now) {
    for (auto it = g_artifacts.begin(); it != g_artifacts.end();) {
        if (it->second.expires <= now) it = g_artifacts.erase(it);
        else ++it;
    }
    while (g_artifacts.size() >= kMaxArtifacts) {
        auto oldest = std::min_element(g_artifacts.begin(), g_artifacts.end(),
            [](const auto& a, const auto& b) { return a.second.expires < b.second.expires; });
        if (oldest == g_artifacts.end()) break;
        g_artifacts.erase(oldest);
    }
}

static json publish_artifact(const std::string& path, const std::string& requested_name = "") {
    std::string canonical;
    if (!allowed_artifact_path(path, canonical)) return nullptr;
    struct stat st;
    if (stat(canonical.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) return nullptr;

    const std::string id = random_hex(16);
    Artifact artifact;
    artifact.path = canonical;
    artifact.name = safe_name(requested_name.empty() ? basename_of(canonical) : requested_name);
    artifact.token = random_hex(24);
    artifact.bytes = static_cast<uint64_t>(st.st_size);
    artifact.modified = st.st_mtime;
    artifact.expires = std::time(nullptr) + kArtifactTtlSeconds;
    {
        std::lock_guard<std::mutex> lock(g_artifacts_mtx);
        prune_artifacts_locked(std::time(nullptr));
        g_artifacts[id] = artifact;
    }
    return {{"artifact_id", id}, {"name", artifact.name}, {"bytes", artifact.bytes},
            {"expires_at", static_cast<int64_t>(artifact.expires) * 1000},
            {"download_url", "http://127.0.0.1:" + std::to_string(g_ctx.public_port) +
                             "/artifacts/" + id},
            {"download_headers", {{"Authorization", "Bearer " + artifact.token}}},
            {"supports_range", true}};
}

static bool artifact_from_request(const Request& req, Artifact& artifact) {
    if (req.path.rfind("/artifacts/", 0) != 0) return false;
    std::string id = req.path.substr(std::string("/artifacts/").size());
    if (id.empty() || id.find('/') != std::string::npos) return false;
    std::string token;
    if (req.has_header("Authorization")) {
        const std::string auth = req.get_header_value("Authorization");
        if (auth.rfind("Bearer ", 0) == 0) token = auth.substr(7);
    }
    if (token.empty() && req.has_header("X-Artifact-Token")) {
        token = req.get_header_value("X-Artifact-Token");
    }
    if (token.empty() && req.has_header("X-Token")) {
        token = req.get_header_value("X-Token");
    }
    std::lock_guard<std::mutex> lock(g_artifacts_mtx);
    prune_artifacts_locked(std::time(nullptr));
    auto it = g_artifacts.find(id);
    if (it == g_artifacts.end() ||
        (!constant_time_equal(token, it->second.token) && !constant_time_equal(token, g_ctx.token))) return false;
    artifact = it->second;
    return true;
}

static void download_artifact(const Request& req, Response& res) {
    Artifact artifact;
    if (!artifact_from_request(req, artifact)) {
        res.status = 404;
        res.set_content("Artifact not found or expired", "text/plain; charset=utf-8");
        return;
    }
    std::string canonical;
    struct stat st;
    if (!allowed_artifact_path(artifact.path, canonical) ||
        stat(canonical.c_str(), &st) != 0 || !S_ISREG(st.st_mode) ||
        static_cast<uint64_t>(st.st_size) != artifact.bytes || st.st_mtime != artifact.modified) {
        res.status = 410;
        res.set_content("Artifact changed or is no longer available", "text/plain; charset=utf-8");
        return;
    }
    const std::string etag = "\"" + std::to_string(artifact.bytes) + "-" +
                             std::to_string(artifact.modified) + "\"";
    if (req.get_header_value("If-None-Match") == etag) {
        res.status = 304;
        res.set_header("ETag", etag);
        return;
    }
    auto file = std::make_shared<std::ifstream>(canonical, std::ios::binary);
    if (!file->good()) {
        res.status = 500;
        res.set_content("Cannot open artifact", "text/plain; charset=utf-8");
        return;
    }
    res.set_header("Accept-Ranges", "bytes");
    res.set_header("Cache-Control", "private, no-store");
    res.set_header("ETag", etag);
    res.set_header("Content-Disposition", "attachment; filename=\"" + artifact.name + "\"");
    res.set_content_provider(
        static_cast<size_t>(artifact.bytes), "application/octet-stream",
        [file](size_t offset, size_t length, DataSink& sink) -> bool {
            char buffer[65536];
            file->clear();
            file->seekg(static_cast<std::streamoff>(offset));
            size_t to_read = std::min(length, sizeof(buffer));
            file->read(buffer, static_cast<std::streamsize>(to_read));
            std::streamsize count = file->gcount();
            return count > 0 && sink.write(buffer, static_cast<size_t>(count));
        },
        [file](bool) {});
}

static bool copy_file(const std::string& src, const std::string& dst, size_t& bytes) {
    std::ifstream in(src, std::ios::binary);
    std::ofstream out(dst, std::ios::binary | std::ios::trunc);
    if (!in.good() || !out.good()) return false;
    char buf[65536];
    bytes = 0;
    while (in.good()) {
        in.read(buf, sizeof(buf));
        auto n = in.gcount();
        if (n <= 0) break;
        out.write(buf, n);
        if (!out.good()) return false;
        bytes += static_cast<size_t>(n);
    }
    return true;
}

static std::string read_file(const std::string& path, size_t max_bytes = 4 * 1024 * 1024) {
    std::ifstream in(path, std::ios::binary);
    if (!in.good()) return "";
    std::string out;
    char buf[8192];
    while (in.good() && out.size() < max_bytes) {
        in.read(buf, std::min(sizeof(buf), max_bytes - out.size()));
        auto n = in.gcount();
        if (n <= 0) break;
        out.append(buf, static_cast<size_t>(n));
    }
    return out;
}

static bool is_valid_utf8(const std::string& value) {
    const auto* p = reinterpret_cast<const unsigned char*>(value.data());
    size_t i = 0;
    while (i < value.size()) {
        unsigned char c = p[i++];
        if (c <= 0x7f) continue;
        int continuation = 0;
        uint32_t codepoint = 0;
        if ((c & 0xe0) == 0xc0) {
            continuation = 1;
            codepoint = c & 0x1f;
            if (codepoint < 2) return false;
        } else if ((c & 0xf0) == 0xe0) {
            continuation = 2;
            codepoint = c & 0x0f;
        } else if ((c & 0xf8) == 0xf0) {
            continuation = 3;
            codepoint = c & 0x07;
        } else {
            return false;
        }
        if (i + continuation > value.size()) return false;
        for (int j = 0; j < continuation; ++j) {
            unsigned char next = p[i++];
            if ((next & 0xc0) != 0x80) return false;
            codepoint = (codepoint << 6) | (next & 0x3f);
        }
        if ((continuation == 2 && codepoint < 0x800) ||
            (continuation == 3 && codepoint < 0x10000) ||
            codepoint > 0x10ffff ||
            (codepoint >= 0xd800 && codepoint <= 0xdfff)) return false;
    }
    return true;
}

static json fold_stack(json event) {
    if (!event.is_object() || !event.contains("stack") || !event["stack"].is_array()) return event;
    static const std::vector<std::string> markers = {
        "com.reconbridge.tracer", "de.robv.android.xposed", "XposedBridge",
        "XC_MethodHook", "LSPHooker_", "java.lang.reflect.Method.invoke",
        "java.lang.reflect.Constructor.newInstance"
    };
    auto& stack = event["stack"];
    size_t folded = 0;
    while (folded < stack.size() && stack[folded].is_string()) {
        const std::string frame = stack[folded].get<std::string>();
        bool framework_frame = false;
        for (const auto& marker : markers) {
            if (frame.find(marker) != std::string::npos) {
                framework_frame = true;
                break;
            }
        }
        if (!framework_frame) break;
        ++folded;
    }
    if (!folded) return event;
    json compact = json::array({"... (" + std::to_string(folded) + " hook framework frames folded)"});
    for (size_t i = folded; i < stack.size(); ++i) compact.push_back(stack[i]);
    event["stack"] = std::move(compact);
    event["stack_folded"] = folded;
    return event;
}

static std::string value_text(const json& value) {
    return value.is_string() ? value.get<std::string>() : value.dump();
}

static std::string event_signature(const json& event) {
    return event.value("hook_id", event.value("class", "?") + "." + event.value("method", "?"));
}

static std::string event_display(const json& event) {
    return event.value("class", "?") + "." + event.value("method", "?");
}

static std::string event_fingerprint(const json& event) {
    if (!event.is_object()) return "";
    std::vector<std::string> parts;
    for (const auto& arg : event.value("args", json::array())) {
        if (arg.is_object()) {
            parts.push_back("a" + value_text(arg.value("index", json(nullptr))) + "=" +
                            value_text(arg.value("value", json(nullptr))));
        }
    }
    if (event.contains("ret")) parts.push_back("ret=" + value_text(event["ret"]));
    for (const auto& path : event.value("paths", json::array())) {
        if (path.is_object()) {
            parts.push_back(path.value("path", "") + "=" +
                            value_text(path.value("value", json(nullptr))));
        }
    }
    for (const auto& field : event.value("fields", json::array())) {
        if (field.is_object()) {
            parts.push_back(field.value("name", "") + "=" +
                            value_text(field.value("value", json(nullptr))));
        }
    }
    std::ostringstream out;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i) out << " | ";
        out << parts[i];
    }
    return out.str();
}

static json prop(const char* type, const json& def = nullptr) {
    json p = {{"type", type}};
    if (!def.is_null()) p["default"] = def;
    return p;
}

static json nullable(const char* type, const json& def = nullptr) {
    json p = {{"anyOf", json::array({json{{"type", type}}, json{{"type", "null"}}})}};
    p["default"] = def;
    return p;
}

static json schema(json properties = json::object(), json required = json::array()) {
    json s = {{"type", "object"}, {"properties", std::move(properties)}};
    if (!required.empty()) s["required"] = std::move(required);
    return s;
}

static json tool(const char* name, const char* description, json input_schema) {
    return {{"name", name}, {"description", description}, {"inputSchema", std::move(input_schema)}};
}

static const json& tools() {
    static const json list = json::array({
        tool("device_status", "探测手机守护进程状态与手机本地 MCP 连接方式。", schema()),
        tool("list_packages", "列出设备安装应用，可按包名过滤。",
             schema({{"name_filter", prop("string", "")}, {"only_third_party", prop("boolean", false)}})),
        tool("pull_apk", "复制应用全部 APK 到手机 ReconBridge 工作目录。",
             schema({{"package_name", prop("string")}}, {"package_name"})),
        tool("pull_libs", "复制应用已落地 native 库到手机工作目录。",
             schema({{"package_name", prop("string")}}, {"package_name"})),
        tool("read_remote_file", "以 root 读取设备文件并保存到手机工作目录，小文本同时内联。",
             schema({{"path", prop("string")}, {"save_as", prop("string", "")},
                     {"max_inline_kb", prop("integer", 64)}}, {"path"})),
        tool("proc_info", "读取 /proc/<pid>/maps|status|cmdline。",
             schema({{"pid", prop("integer")}, {"what", prop("string", "status")}}, {"pid"})),
        tool("remote_shell", "以 root 执行 ReconBridge 白名单命令。",
             schema({{"argv", nullable("array")}, {"cmd", prop("string", "")}})),
        tool("decompile_apk", "使用手机 toolpack 中的 jadx 反编译 APK。",
             schema({{"apk_path", prop("string")}, {"output_dir", prop("string", "")}}, {"apk_path"})),
        tool("dexkit_search", "使用手机 toolpack 对 APK 做 DexKit 结构化搜索。",
             schema({{"apk_path", prop("string")}, {"query", prop("object")}}, {"apk_path", "query"})),
        tool("ghidra_analyze", "使用手机 native 分析 toolpack 分析共享库。",
             schema({{"so_path", prop("string")}, {"options", nullable("object")}}, {"so_path"})),
        tool("hermes_decompile", "使用手机 toolpack 反编译 Hermes 字节码。",
             schema({{"bundle_path", prop("string")}, {"output_dir", prop("string", "")}}, {"bundle_path"})),
        tool("post_hook", "下发 native 或 Java hook 配置。",
             schema({{"config", prop("object")}}, {"config"})),
        tool("list_hooks", "列出当前 hook 配置。", schema()),
        tool("unhook", "移除某包全部 hook 或指定 hook id。",
             schema({{"package", prop("string")}, {"hook_id", prop("string", "")}}, {"package"})),
        tool("collect_events", "收集 hook 命中事件，支持最近事件补捞与早停。",
             schema({{"seconds", prop("number", 10.0)}, {"max_events", prop("integer", 200)},
                     {"until_first_hit", prop("boolean", false)}, {"until_n_events", prop("integer", 0)},
                     {"fold_stack", prop("boolean", true)}, {"include_recent", prop("boolean", false)},
                     {"since_seq", prop("integer", 0)}, {"quiet_ms", prop("integer", 0)}})),
        tool("capture_scenario", "捕获并保存一个 hook 事件场景。",
             schema({{"name", prop("string")}, {"seconds", prop("number", 20.0)},
                     {"quiet_ms", prop("integer", 1500)}, {"max_events", prop("integer", 500)},
                     {"fold_stack", prop("boolean", true)}}, {"name"})),
        tool("list_scenarios", "列出手机工作区已保存场景。", schema()),
        tool("diff_scenarios", "比较两个场景的方法和参数差异。",
             schema({{"a", prop("string")}, {"b", prop("string")}}, {"a", "b"})),
        tool("recent_events", "从设备事件环形缓冲补捞最近命中。",
             schema({{"limit", prop("integer", 50)}, {"since_seq", prop("integer", 0)}})),
        tool("trace_java", "下发 Java 方法 trace 并采集命中。",
             schema({{"package", prop("string")}, {"class_name", prop("string")}, {"method", prop("string")},
                     {"params", nullable("array")}, {"args_render", prop("string", "tostring")},
                     {"capture_args", nullable("array")}, {"fields", nullable("array")}, {"paths", nullable("array")},
                     {"this", prop("string", "class")}, {"ret", prop("boolean", true)},
                     {"when", prop("string", "after")}, {"stack", prop("boolean", false)},
                     {"hook_id", prop("string", "")}, {"debug", prop("boolean", false)},
                     {"restart", prop("boolean", true)}, {"seconds", prop("number", 12.0)},
                     {"max_events", prop("integer", 200)}, {"until_first_hit", prop("boolean", false)},
                     {"until_n_events", prop("integer", 0)}, {"fold_stack", prop("boolean", true)},
                     {"include_recent", prop("boolean", false)}, {"since_seq", prop("integer", 0)},
                     {"hot", prop("boolean", false)}}, {"package", "class_name", "method"})),
        tool("patch_java", "实时替换 Java 参数/返回值/深层字段，条件执行与动作流水线。",
             schema({{"package", prop("string")}, {"class_name", prop("string")}, {"method", prop("string")},
                     {"params", nullable("array")}, {"replace_args", nullable("array")},
                     {"replace_return", nullable("object")}, {"mutate_return", nullable("array")},
                     {"condition", nullable("object")}, {"before_actions", nullable("array")},
                     {"after_actions", nullable("array")}, {"action", nullable("object")},
                     {"skip_original", prop("boolean", false)},
                     {"trace", prop("boolean", true)}, {"capture_args", nullable("array")},
                     {"this", prop("string", "class")}, {"when", prop("string", "after")},
                     {"hook_id", prop("string", "")}, {"debug", prop("boolean", false)},
                     {"restart", prop("boolean", true)}, {"seconds", prop("number", 0.0)},
                     {"max_events", prop("integer", 100)}}, {"package", "class_name", "method"})),
        tool("dump_dex", "下发内存 DEX dump hook。",
             schema({{"package", prop("string")}, {"symbol", prop("string", "")},
                     {"offset", prop("string", "")}, {"base_arg", prop("integer", 0)},
                     {"size_arg", prop("integer", 1)}, {"lib", prop("string", "libart.so")},
                     {"restart", prop("boolean", true)}}, {"package"})),
        tool("list_dumps", "列出设备已落盘内存 dump。", schema()),
        tool("list_artifacts", "列出手机工作目录的 APK、SO 和分析产物。",
             schema({{"package_name", prop("string", "")}})),
        tool("toolchain_status", "检查手机本地 jadx、DexKit、native 和 Hermes 工具包。", schema())
    });
    return list;
}

static json http_get(const std::string& path, const Params& params = {}) {
    Client c("127.0.0.1", g_ctx.internal_port);
    c.set_connection_timeout(5);
    c.set_read_timeout(180);
    Headers h = {{"X-Token", g_ctx.token}};
    auto r = c.Get(path, params, h);
    if (!r) throw std::runtime_error("internal GET failed: " + path);
    if (r->status != 200) throw std::runtime_error("internal GET " + path + " -> " + std::to_string(r->status) + ": " + r->body);
    try { return json::parse(r->body); }
    catch (...) { return json{{"content", r->body}}; }
}

static json http_post(const std::string& path, const json& body) {
    Client c("127.0.0.1", g_ctx.internal_port);
    c.set_connection_timeout(5);
    c.set_read_timeout(180);
    Headers h = {{"X-Token", g_ctx.token}};
    auto r = c.Post(path, h, body.dump(), "application/json");
    if (!r) throw std::runtime_error("internal POST failed: " + path);
    if (r->status != 200 && r->status != 504)
        throw std::runtime_error("internal POST " + path + " -> " + std::to_string(r->status) + ": " + r->body);
    return json::parse(r->body);
}

static json recent_events(int limit, uint64_t since, bool fold = true) {
    Params p = {{"limit", std::to_string(std::max(0, limit))}};
    if (since) p.emplace("since_seq", std::to_string(since));
    json data = http_get("/recent", p);
    if (fold) {
        json events = json::array();
        for (auto& event : data.value("events", json::array())) events.push_back(fold_stack(event));
        data["events"] = std::move(events);
        data["count"] = data["events"].size();
    }
    return data;
}

static json collect_events(const json& a) {
    double seconds = std::clamp(a.value("seconds", 10.0), 0.0, 300.0);
    int max_events = std::clamp(a.value("max_events", 200), 1, 5000);
    bool until_first = a.value("until_first_hit", false);
    int until_n = std::max(0, a.value("until_n_events", 0));
    bool include_recent = a.value("include_recent", false);
    uint64_t since = a.value("since_seq", static_cast<uint64_t>(0));
    int quiet_ms = std::max(0, a.value("quiet_ms", 0));
    bool should_fold = a.value("fold_stack", true);
    json events = json::array();
    std::set<std::string> seen;
    uint64_t cursor = since;
    auto add = [&](const json& data) {
        cursor = std::max(cursor, data.value("latest_seq", static_cast<uint64_t>(0)));
        for (auto e : data.value("events", json::array())) {
            if (should_fold) e = fold_stack(std::move(e));
            std::string k = e.dump();
            if (seen.insert(k).second && static_cast<int>(events.size()) < max_events) events.push_back(std::move(e));
        }
    };
    if (include_recent) add(recent_events(max_events, since, false));
    else if (!since) cursor = recent_events(0, 0, false).value("latest_seq", static_cast<uint64_t>(0));

    auto start = std::chrono::steady_clock::now();
    auto last_event = start;
    auto early_deadline = std::chrono::steady_clock::time_point::max();
    while (std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count() < seconds) {
        size_t before = events.size();
        add(recent_events(max_events - static_cast<int>(events.size()), cursor, false));
        if (events.size() > before) last_event = std::chrono::steady_clock::now();
        int hits = 0;
        for (const auto& e : events) if (e.is_object() && e.contains("hook_id")) ++hits;
        int threshold = until_n > 0 ? until_n : 1;
        auto now = std::chrono::steady_clock::now();
        if ((until_first || until_n > 0) && hits >= threshold &&
            early_deadline == std::chrono::steady_clock::time_point::max()) {
            early_deadline = now + std::chrono::milliseconds(250);
        }
        if (now >= early_deadline) break;
        if (quiet_ms > 0 && hits > 0 &&
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - last_event).count() >= quiet_ms) break;
        if (static_cast<int>(events.size()) >= max_events) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(120));
    }
    return {{"count", events.size()}, {"seconds", seconds},
            {"early_return", until_first || until_n > 0}, {"events", events}, {"latest_seq", cursor}};
}

static json run_toolpack(const std::string& name, const json& args) {
    std::string exe = g_ctx.base_dir + "/toolchains/bin/" + name;
    if (access(exe.c_str(), X_OK) != 0) {
        return {{"ok", false}, {"error", "手机分析工具未安装"}, {"tool", name},
                {"expected_path", exe},
                {"hint", "安装 ReconBridge Mobile Toolpack 后重试；设备/Hook 类工具不受影响"}};
    }
    std::filesystem::create_directories(g_ctx.work_dir + "/jobs");
    std::string job = random_hex(8);
    std::string input = g_ctx.work_dir + "/jobs/" + job + ".json";
    std::string output = g_ctx.work_dir + "/jobs/" + job + ".out.json";
    { std::ofstream f(input); f << args.dump(); }
    pid_t pid = fork();
    if (pid == 0) {
        execl(exe.c_str(), exe.c_str(), "--input", input.c_str(), "--output", output.c_str(), nullptr);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return {{"ok", false}, {"tool", name}, {"exit", WIFEXITED(status) ? WEXITSTATUS(status) : -1}};
    try { return json::parse(read_file(output)); }
    catch (...) { return {{"ok", false}, {"error", "toolpack 未输出合法 JSON"}, {"output", output}}; }
}

static json list_artifacts(const std::string& package_name) {
    json packages = json::array();
    std::filesystem::path root(g_ctx.work_dir);
    if (!std::filesystem::exists(root)) return {{"workdir", g_ctx.work_dir}, {"count", 0}, {"packages", packages}};
    auto scan = [&](const std::filesystem::path& d) {
        json apks = json::array(), libs = json::array(), downloads = json::array();
        json jadx = json::array(), hermes = json::array();
        for (auto& e : std::filesystem::recursive_directory_iterator(d, std::filesystem::directory_options::skip_permission_denied)) {
            auto s = e.path().string();
            if (e.is_regular_file() && e.path().extension() == ".apk") {
                apks.push_back(s);
                json artifact = publish_artifact(s);
                if (!artifact.is_null()) { artifact["kind"] = "apk"; artifact["device_path"] = s; downloads.push_back(std::move(artifact)); }
            }
            if (e.is_regular_file() && e.path().extension() == ".so") {
                libs.push_back(s);
                json artifact = publish_artifact(s);
                if (!artifact.is_null()) { artifact["kind"] = "so"; artifact["device_path"] = s; downloads.push_back(std::move(artifact)); }
            }
            if (e.is_directory() && s.size() >= 5 && s.substr(s.size() - 5) == "-jadx") jadx.push_back(s);
            if (e.is_directory() && s.size() >= 7 && s.substr(s.size() - 7) == "-hermes") hermes.push_back(s);
        }
        return json{{"package", d.filename().string()}, {"apks", apks}, {"libs", libs},
                    {"downloads", downloads}, {"jadx_dirs", jadx}, {"hermes_dirs", hermes},
                    {"has_apk", !apks.empty()}, {"has_decompiled", !jadx.empty()}};
    };
    if (!package_name.empty()) {
        if (!valid_package(package_name)) throw std::runtime_error("invalid package_name");
        auto d = root / package_name;
        if (!std::filesystem::is_directory(d)) return {{"package", package_name}, {"exists", false}};
        json r = scan(d); r["exists"] = true; return r;
    }
    for (auto& e : std::filesystem::directory_iterator(root))
        if (e.is_directory() && e.path().filename() != "scenarios" && e.path().filename() != "jobs") packages.push_back(scan(e.path()));
    return {{"workdir", g_ctx.work_dir}, {"count", packages.size()}, {"packages", packages}};
}

static json invoke_tool(const std::string& name, const json& a) {
    if (name == "device_status") {
        return {{"transport", "mobile-streamable-http"},
                {"base_url", "http://127.0.0.1:" + std::to_string(g_ctx.public_port) + "/mcp"},
                {"health", http_get("/health")}};
    }
    if (name == "list_packages") {
        json data = http_get("/packages"), out = json::array();
        std::string filter = a.value("name_filter", "");
        std::transform(filter.begin(), filter.end(), filter.begin(), ::tolower);
        bool third = a.value("only_third_party", false);
        for (auto& p : data.value("packages", json::array())) {
            std::string pkg = p.value("package", ""), low = pkg;
            std::transform(low.begin(), low.end(), low.begin(), ::tolower);
            if (third && p.value("system", false)) continue;
            if (!filter.empty() && low.find(filter) == std::string::npos) continue;
            out.push_back(p);
        }
        return {{"count", out.size()}, {"total_installed", data.value("count", 0)}, {"packages", out}};
    }
    if (name == "pull_apk" || name == "pull_libs") {
        std::string pkg = a.value("package_name", "");
        if (!valid_package(pkg)) throw std::runtime_error("invalid package_name");
        bool apk = name == "pull_apk";
        json info = http_get(apk ? "/apk" : "/libs", {{"pkg", pkg}});
        json source = info.value(apk ? "apks" : "libs", json::array());
        std::string dir = g_ctx.work_dir + "/" + pkg + (apk ? "/apk" : "/libs");
        std::filesystem::create_directories(dir);
        json files = json::array();
        for (auto& item : source) {
            std::string src = item.value("path", ""), nm = item.value("name", basename_of(src));
            std::string dst = dir + "/" + safe_name(nm);
            size_t bytes = 0;
            bool ok = copy_file(src, dst, bytes);
            json file = {{"name", nm}, {"local_path", dst}, {"bytes", bytes}, {"size_match", ok}};
            if (ok) {
                json artifact = publish_artifact(dst, nm);
                if (!artifact.is_null()) file["artifact"] = std::move(artifact);
            }
            files.push_back(std::move(file));
        }
        return {{"package", pkg}, {"count", files.size()}, {"dir", dir}, {"files", files}, {"note", info.value("note", "")}};
    }
    if (name == "read_remote_file") {
        std::string path = a.value("path", ""), save = a.value("save_as", "");
        if (path.empty() || path[0] != '/') throw std::runtime_error("path must be absolute");
        if (save.empty()) save = g_ctx.work_dir + "/files/" + safe_name(basename_of(path));
        std::filesystem::create_directories(std::filesystem::path(save).parent_path());
        size_t bytes = 0;
        if (!copy_file(path, save, bytes)) throw std::runtime_error("cannot read file: " + path);
        json r = {{"remote_path", path}, {"local_path", save}, {"bytes", bytes}};
        json artifact = publish_artifact(save);
        if (!artifact.is_null()) r["artifact"] = std::move(artifact);
        size_t lim = static_cast<size_t>(std::max(0, a.value("max_inline_kb", 64))) * 1024;
        if (bytes <= lim) {
            std::string inline_value = read_file(save, lim);
            if (is_valid_utf8(inline_value)) {
                r["text"] = std::move(inline_value);
            } else {
                r["text"] = nullptr;
                r["hint"] = "Binary file was saved but not inlined; see local_path";
            }
        }
        return r;
    }
    if (name == "proc_info") {
        int pid = a.value("pid", -1); std::string what = a.value("what", "status");
        if (pid <= 0 || (what != "maps" && what != "status" && what != "cmdline")) throw std::runtime_error("invalid proc request");
        return {{"pid", pid}, {"what", what}, {"content", read_file("/proc/" + std::to_string(pid) + "/" + what)}};
    }
    if (name == "remote_shell") {
        json body = json::object();
        if (a.contains("argv") && a["argv"].is_array()) body["argv"] = a["argv"];
        else if (!a.value("cmd", "").empty()) body["cmd"] = a["cmd"];
        else throw std::runtime_error("需要 argv 或 cmd");
        return http_post("/shell", body);
    }
    if (name == "decompile_apk") return run_toolpack("jadx", a);
    if (name == "dexkit_search") return run_toolpack("dexkit-search", a);
    if (name == "ghidra_analyze") return run_toolpack("native-analyze", a);
    if (name == "hermes_decompile") return run_toolpack("hermes-decompile", a);
    if (name == "post_hook") {
        json cfg;
        if (a.contains("config")) {
            if (a["config"].is_string()) {
                try {
                    cfg = json::parse(a["config"].get<std::string>());
                } catch (...) {
                    return {{"ok", false}, {"error", "Invalid argument: 'config' is a string but failed to parse as JSON."}};
                }
            } else if (a["config"].is_object()) {
                cfg = a["config"];
            }
        } else if (a.contains("package") && a.contains("targets")) {
            cfg = a;
        }
        if (!cfg.is_object() || cfg.empty()) {
            return {{"ok", false}, {"error", "Invalid argument: 'config' must be a JSON object (dict)."}};
        }
        return http_post("/hook", cfg);
    }
    if (name == "list_hooks") return http_get("/hooks");
    if (name == "unhook") {
        json body = {{"package", a.value("package", "")}};
        if (!a.value("hook_id", "").empty()) body["id"] = a["hook_id"];
        return http_post("/unhook", body);
    }
    if (name == "collect_events") return collect_events(a);
    if (name == "recent_events") return recent_events(a.value("limit", 50), a.value("since_seq", static_cast<uint64_t>(0)));
    if (name == "capture_scenario") {
        uint64_t cursor = recent_events(0, 0, false).value("latest_seq", static_cast<uint64_t>(0));
        json opts = a; opts["include_recent"] = true; opts["since_seq"] = cursor;
        json captured = collect_events(opts);
        std::string nm = safe_name(a.value("name", "scenario"), 64);
        std::string dir = g_ctx.work_dir + "/scenarios";
        std::filesystem::create_directories(dir);
        json stored = {{"name", a.value("name", nm)},
                       {"captured_at", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count()},
                       {"since_seq", cursor}, {"count", captured["count"]}, {"events", captured["events"]}};
        std::string path = dir + "/" + nm + ".json";
        { std::ofstream f(path); f << stored.dump(1); }
        std::map<std::string, int> methods;
        for (auto& e : stored["events"]) methods[e.value("hook_id", e.value("class", "?") + "." + e.value("method", "?"))]++;
        return {{"name", stored["name"]}, {"count", stored["count"]}, {"distinct_methods", methods.size()},
                {"methods", methods}, {"saved", path},
                {"note", stored["count"].get<int>() == 0 ? "No events captured; verify hooks and trigger the action during the capture window" : ""}};
    }
    if (name == "list_scenarios") {
        json out = json::array(); std::string dir = g_ctx.work_dir + "/scenarios";
        if (std::filesystem::is_directory(dir)) for (auto& e : std::filesystem::directory_iterator(dir)) {
            if (e.path().extension() != ".json") continue;
            try { auto s = json::parse(read_file(e.path().string())); out.push_back({{"name", s.value("name", e.path().stem().string())}, {"count", s.value("count", 0)}, {"captured_at", s.value("captured_at", 0)}, {"path", e.path().string()}}); } catch (...) {}
        }
        return {{"count", out.size()}, {"scenarios", out}};
    }
    if (name == "diff_scenarios") {
        auto load = [&](const std::string& n) { return json::parse(read_file(g_ctx.work_dir + "/scenarios/" + safe_name(n, 64) + ".json")); };
        json sa = load(a.value("a", "")), sb = load(a.value("b", ""));
        struct Stats { std::string display; int count = 0; std::set<std::string> fingerprints; };
        auto index = [](const json& s) {
            std::map<std::string, Stats> m;
            for (auto& e : s.value("events", json::array())) {
                if (!e.is_object()) continue;
                std::string sig = event_signature(e);
                auto& stats = m[sig];
                stats.display = event_display(e);
                ++stats.count;
                std::string fp = event_fingerprint(e);
                if (!fp.empty()) stats.fingerprints.insert(std::move(fp));
            }
            return m;
        };
        auto ia = index(sa), ib = index(sb); json only_a=json::array(), only_b=json::array(), both=json::array(), diff=json::array();
        for (auto& [s,v] : ia) {
            if (!ib.count(s)) {
                only_a.push_back({{"method",v.display},{"sig",s},{"hits",v.count}});
                continue;
            }
            auto& bv = ib[s];
            both.push_back({{"method",v.display},{"sig",s},{"a_hits",v.count},{"b_hits",bv.count}});
            json av = json::array(), bvals = json::array();
            for (const auto& fp : v.fingerprints) if (!bv.fingerprints.count(fp) && av.size() < 8) av.push_back(fp);
            for (const auto& fp : bv.fingerprints) if (!v.fingerprints.count(fp) && bvals.size() < 8) bvals.push_back(fp);
            if (!av.empty() || !bvals.empty()) diff.push_back({{"method",v.display},{"sig",s},{"only_in_a_values",av},{"only_in_b_values",bvals}});
        }
        for (auto& [s,v] : ib) if (!ia.count(s)) only_b.push_back({{"method",v.display},{"sig",s},{"hits",v.count}});
        auto by_hits=[](const json& x,const json& y){return x.value("hits",0)>y.value("hits",0);};
        std::sort(only_a.begin(),only_a.end(),by_hits); std::sort(only_b.begin(),only_b.end(),by_hits);
        return {{"a",a.value("a","")},{"b",a.value("b","")},{"a_count",sa.value("count",0)},{"b_count",sb.value("count",0)},
                {"only_in_a",only_a},{"only_in_b",only_b},{"in_both",both},{"differing_args",diff},
                {"summary",std::to_string(only_a.size())+" 个方法只在 A，"+std::to_string(only_b.size())+" 个只在 B，"+std::to_string(diff.size())+" 个参数不同"}};
    }
    if (name == "trace_java") {
        json cap = {{"this", a.value("this", "class")}, {"when", a.value("when", "after")}, {"stack", a.value("stack", false)}};
        if (a.contains("capture_args") && !a["capture_args"].is_null()) cap["args"] = a["capture_args"]; else cap["all_args"] = true;
        if (a.value("ret", true)) cap["ret"] = {{"capture", true}, {"render", a.value("args_render", "tostring")}};
        if (a.contains("fields") && !a["fields"].is_null()) cap["fields"] = a["fields"];
        if (a.contains("paths") && !a["paths"].is_null()) cap["paths"] = a["paths"];
        std::string cls = a.value("class_name", ""), method = a.value("method", "");
        std::string short_cls = cls.substr(cls.find_last_of('.') == std::string::npos ? 0 : cls.find_last_of('.') + 1);
        json target = {{"kind","java"},{"id",a.value("hook_id", short_cls+"_"+method)}, {"class",cls},{"method",method},{"capture",cap}};
        if (a.contains("params") && !a["params"].is_null()) target["params"] = a["params"];
        json cfg = {{"package",a.value("package","")},{"restart",a.value("restart",true)},{"debug",a.value("debug",false)},{"targets",json::array({target})}};
        if (a.value("hot",false)) { cfg["restart"]=false; cfg["mode"]="append"; }
        json posted = http_post("/hook", cfg), ev = collect_events(a);
        return {{"posted",posted},{"count",ev["count"]},{"seconds",a.value("seconds",12.0)},{"early_return",a.value("until_first_hit",false)||a.value("until_n_events",0)>0},{"events",ev["events"]}};
    }
    if (name == "patch_java") {
        std::string cls=a.value("class_name",""), method=a.value("method",""); std::string short_cls=cls.substr(cls.find_last_of('.')==std::string::npos?0:cls.find_last_of('.')+1);
        json cap={{"this",a.value("this","class")},{"when",a.value("trace",true)?a.value("when","after"):"none"}};
        if (a.contains("capture_args")&&!a["capture_args"].is_null()) cap["args"]=a["capture_args"]; else if(a.value("trace",true)) cap["all_args"]=true;
        if(a.value("trace",true)) cap["ret"]={{"capture",true},{"render","tostring"}};
        json target={{"kind","java"},{"id",a.value("hook_id",short_cls+"_"+method)},{"class",cls},{"method",method},{"capture",cap}};
        if(a.contains("params")&&!a["params"].is_null()) target["params"]=a["params"];
        json action=a.contains("action")&&a["action"].is_object()?a["action"]:json::object();
        if(a.contains("replace_args")&&!a["replace_args"].is_null()) action["replace_args"]=a["replace_args"];
        if(a.contains("replace_return")&&!a["replace_return"].is_null()) action["replace_return"]=a["replace_return"];
        if(a.contains("mutate_return")&&!a["mutate_return"].is_null()) action["mutate_return"]=a["mutate_return"];
        if(a.contains("condition")&&!a["condition"].is_null()) action["condition"]=a["condition"];
        if(a.contains("before_actions")&&!a["before_actions"].is_null()) action["before_actions"]=a["before_actions"];
        if(a.contains("after_actions")&&!a["after_actions"].is_null()) action["after_actions"]=a["after_actions"];
        if(a.value("skip_original",false)) action["skip_original"]=true; if(!action.empty()) target["action"]=action;
        json cfg={{"package",a.value("package","")},{"restart",a.value("restart",true)},{"debug",a.value("debug",false)},{"targets",json::array({target})}};
        json posted=http_post("/hook",cfg), result={{"posted",posted}}; if(a.value("seconds",0.0)>0){json ev=collect_events(a);result["count"]=ev["count"];result["seconds"]=a["seconds"];result["events"]=ev["events"];} return result;
    }
    if (name == "dump_dex") {
        json body={{"package",a.value("package","")},{"lib",a.value("lib","libart.so")},{"base_arg",a.value("base_arg",0)},{"size_arg",a.value("size_arg",1)},{"restart",a.value("restart",true)}};
        if(!a.value("symbol","").empty()) body["symbol"]=a["symbol"]; if(!a.value("offset","").empty()) body["offset"]=a["offset"]; return http_post("/dump_dex",body);
    }
    if (name == "list_dumps") {
        json result = http_get("/dumps");
        for (auto& dump : result["dumps"]) {
            if (!dump.is_object()) continue;
            json artifact = publish_artifact(dump.value("path", ""), dump.value("name", ""));
            if (!artifact.is_null()) dump["artifact"] = std::move(artifact);
        }
        return result;
    }
    if (name == "list_artifacts") return list_artifacts(a.value("package_name", ""));
    if (name == "toolchain_status") {
        auto chk=[](const char* n){std::string p=g_ctx.base_dir+"/toolchains/bin/"+n;return json{{"ready",access(p.c_str(),X_OK)==0},{"path",p}};};
        json jadx=chk("jadx"), dexkit=chk("dexkit-search"), ghidra=chk("native-analyze"), hermes=chk("hermes-decompile");
        auto ready_path=[](const json& state)->json{return state.value("ready",false)?state["path"]:json(nullptr);};
        return {{"jadx",ready_path(jadx)},
                {"androguard",dexkit.value("ready",false)?json("mobile-toolpack"):json(nullptr)},
                {"ghidra_headless",ready_path(ghidra)}, {"ghidra_jdk21",nullptr},
                {"system_java",nullptr}, {"hermes",ready_path(hermes)},
                {"platform","android"}, {"workdir",g_ctx.work_dir},
                {"mobile",{{"jadx",jadx},{"dexkit",dexkit},{"ghidra_headless",ghidra},{"hermes",hermes}}},
                {"hints",{{"jadx",jadx.value("ready",false)?json(nullptr):json("Install ReconBridge Mobile Toolpack")},
                           {"dexkit",dexkit.value("ready",false)?json(nullptr):json("Install ReconBridge Mobile Toolpack")},
                           {"ghidra",ghidra.value("ready",false)?json(nullptr):json("Install ReconBridge Mobile Toolpack")},
                           {"hermes",hermes.value("ready",false)?json(nullptr):json("Install ReconBridge Mobile Toolpack")}}}};
    }
    throw std::runtime_error("unknown tool: " + name);
}

static json rpc_error(const json& id, int code, const std::string& message) {
    return {{"jsonrpc", "2.0"}, {"id", id}, {"error", {{"code", code}, {"message", message}}}};
}

static json rpc_result(const json& id, json result) {
    return {{"jsonrpc", "2.0"}, {"id", id}, {"result", std::move(result)}};
}

static bool session_valid(const Request& req) {
    auto sid = req.get_header_value("Mcp-Session-Id");
    if (sid.empty()) return false;
    std::lock_guard<std::mutex> lk(g_sessions_mtx);
    return g_sessions.count(sid) > 0;
}

static void post_mcp(const Request& req, Response& res) {
    json msg;
    try { msg = json::parse(req.body); }
    catch (...) { res.status=400; res.set_content(rpc_error(nullptr,-32700,"Parse error").dump(),"application/json"); return; }
    if (!msg.is_object() || msg.value("jsonrpc", "") != "2.0" || !msg.contains("method")) {
        res.status=400; res.set_content(rpc_error(msg.contains("id")?msg["id"]:json(nullptr),-32600,"Invalid Request").dump(),"application/json"); return;
    }
    json id = msg.contains("id") ? msg["id"] : json(nullptr);
    std::string method = msg.value("method", "");
    if (method == "initialize") {
        std::string requested = msg.value("params",json::object()).value("protocolVersion","2025-06-18");
        static const std::set<std::string> supported={"2024-11-05","2025-03-26","2025-06-18","2025-11-25"};
        std::string version=supported.count(requested)?requested:"2025-11-25";
        std::string sid=random_hex(); {std::lock_guard<std::mutex> lk(g_sessions_mtx);g_sessions.insert(sid);} res.set_header("Mcp-Session-Id",sid);
        res.set_content(rpc_result(id,{{"protocolVersion",version},{"capabilities",{{"tools",json::object()}}},{"serverInfo",{{"name","reconbridge-mobile"},{"version","MCP1.0"}}},{"instructions","ReconBridge 手机本地逆向工具。仅分析自有或明确授权的设备与应用。"}}).dump(),"application/json"); return;
    }
    if (!session_valid(req)) {res.status=404;res.set_content(rpc_error(id,-32001,"Invalid or missing Mcp-Session-Id").dump(),"application/json");return;}
    if (method == "notifications/initialized" || method == "notifications/cancelled") {res.status=202;return;}
    if (method == "ping") {res.set_content(rpc_result(id,json::object()).dump(),"application/json");return;}
    if (method == "tools/list") {res.set_content(rpc_result(id,{{"tools",tools()}}).dump(),"application/json");return;}
    if (method == "tools/call") {
        auto params=msg.value("params",json::object()); std::string name=params.value("name",""); json args=params.value("arguments",json::object());
        try {json value=invoke_tool(name,args);json result={{"content",json::array({json{{"type","text"},{"text",value.dump(2)}}})},{"structuredContent",value},{"isError",false}};res.set_content(rpc_result(id,result).dump(),"application/json");}
        catch(const std::exception& e){json value={{"error",e.what()},{"tool",name}};json result={{"content",json::array({json{{"type","text"},{"text",value.dump(2)}}})},{"structuredContent",value},{"isError",true}};res.set_content(rpc_result(id,result).dump(),"application/json");} return;
    }
    res.set_content(rpc_error(id,-32601,"Method not found").dump(),"application/json");
}

}  // namespace

bool authorize_artifact_request(const Request& request) {
    Artifact artifact;
    return artifact_from_request(request, artifact);
}

void register_routes(Server& server, const std::string& base_dir, int public_port,
                     int internal_port, const std::string& token) {
    g_ctx={base_dir,base_dir+"/work",token,public_port,internal_port}; std::filesystem::create_directories(g_ctx.work_dir);
    { std::lock_guard<std::mutex> lk(g_sessions_mtx); g_sessions.clear(); }
    { std::lock_guard<std::mutex> lk(g_artifacts_mtx); g_artifacts.clear(); }
    server.Post("/mcp", post_mcp);
    server.Get("/mcp", [](const Request&, Response& res){res.status=405;res.set_header("Allow","POST, DELETE");res.set_content("Standalone SSE stream is not required by this server","text/plain");});
    server.Delete("/mcp", [](const Request& req, Response& res){auto sid=req.get_header_value("Mcp-Session-Id");{std::lock_guard<std::mutex> lk(g_sessions_mtx);g_sessions.erase(sid);}res.status=204;});
    server.Get("/artifacts/:id", download_artifact);
}

}  // namespace mobile_mcp

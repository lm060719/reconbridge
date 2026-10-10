// Linux host integration: actual daemon handlers and socket framing, no Android.
#include "../src/dynamic.cpp"
#include <cassert>
#include <filesystem>
#include <iostream>

static void send_frame(int fd, char type, const std::string& payload) {
    uint32_t size = static_cast<uint32_t>(payload.size());
    assert(dynamic::sock_write_full(fd, &type, 1));
    assert(dynamic::sock_write_full(fd, &size, 4));
    assert(dynamic::sock_write_full(fd, payload.data(), payload.size()));
}
static json read_reload(int fd) {
    char type; uint32_t size;
    assert(dynamic::sock_read_full(fd, &type, 1) && type == 'R');
    assert(dynamic::sock_read_full(fd, &size, 4) && size < 65536);
    std::string payload(size, 0);
    assert(dynamic::sock_read_full(fd, payload.data(), size));
    return json::parse(payload);
}
static json request(bool unhook, const json& body) {
    httplib::Request req;
    httplib::Response res;
    req.body = body.dump();
    if (unhook) dynamic::handle_unhook(req, res);
    else dynamic::handle_hook(req, res);
    assert(res.status == 200);
    return json::parse(res.body);
}
static json target(const std::string& id) {
    return {{"id", id}, {"kind", "native"}, {"lib", "libsample.so"}, {"symbol", id}};
}
int main() {
    char path[] = "/tmp/rb-native-ipc-XXXXXX";
    char* directory = mkdtemp(path);
    assert(directory);
    using namespace dynamic;
    g_base_dir = directory;
    g_hooks_dir = g_base_dir + "/hooks";
    g_programs_dir = g_base_dir + "/runtime_programs";
    g_program_policy_dir = g_base_dir + "/runtime_program_policies";
    std::filesystem::create_directory(g_hooks_dir);
    std::filesystem::create_directory(g_programs_dir);
    std::filesystem::create_directory(g_program_policy_dir);
    const std::string pkg = "com.example.app", process = pkg + ":worker";
    for (int scenario = 0; scenario < 3; ++scenario) {
        request(false, {{"package", pkg}, {"targets", json::array({target("old")})}});
        int pair[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
        timeval timeout{5, 0};
        for (int fd : pair) {
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        }
        std::thread server([fd = pair[0]] { inject_client(fd); });
        const int fd = pair[1];
        uint32_t size = process.size();
        assert(sock_write_full(fd, &size, 4) && sock_write_full(fd, process.data(), size));
        uint8_t has;
        assert(sock_read_full(fd, &has, 1) && has == 1);
        assert(sock_read_full(fd, &size, 4));
        std::string initial(size, 0);
        assert(sock_read_full(fd, initial.data(), size));
        assert(json::parse(initial)["targets"][0]["id"] == "old");

        // Write/delete after fetch, before H. H must replay the CURRENT config.
        if (scenario == 1) request(true, {{"package", pkg}});
        else request(false, {{"package", pkg}, {"targets", json::array({target("new")})}});
        send_frame(fd, 'H', scenario == 2 ? "" : R"({"kind":"native"})");
        auto latest = read_reload(fd);
        if (scenario == 1) assert(latest["targets"].empty());
        else assert(latest["targets"][0]["id"] == "new");
        auto rows = runtime_status_snapshot(pkg)["processes"];
        assert(rows.size() == 1 && rows[0]["live_reconcile"] == true);
        assert(rows[0]["kind"] == (scenario == 2 ? "java" : "native"));

        auto added = request(false, {{"package", pkg}, {"mode", "append"},
                                     {"targets", json::array({target("added")})}});
        assert(added["hot_injected"] == 1 && added["runtime_effect_confirmed"] == false);
        latest = read_reload(fd);
        assert(latest["targets"].size() == (scenario == 1 ? 1 : 2));
        auto removed = request(true, {{"package", pkg}, {"id", "added"}});
        assert(removed["hot_unhooked"] == 1 && removed["runtime_effect_confirmed"] == false);
        latest = read_reload(fd);
        assert(latest["targets"].size() == (scenario == 1 ? 0 : 1));
        request(true, {{"package", pkg}});
        assert(read_reload(fd)["targets"].empty());

        // Status frames from a live native connection stay tagged as native.
        send_frame(fd, 'S', R"({"kind":"native","native_status_version":2,"hooks":[],"config_revision":4})");
        bool received = false;
        for (int i = 0; i < 100; ++i) {
            rows = runtime_status_snapshot(pkg)["processes"];
            if (rows[0]["runtime"].is_object()) { received = true; break; }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        assert(received && rows[0]["runtime"]["config_revision"] == 4);
        if (scenario == 0) {
            // Actual framed JNI ingress and HTTP handler: connection-owned
            // package identity, re-registration, unregister and disconnect.
            json registration = {{"type","jni_registration"}, {"package","wrong.package"},
                {"process_instance","test-instance"}, {"class_id","1"}, {"class","sample.Native"},
                {"method","foo"}, {"signature","()I"}, {"address","0x1000"}};
            send_frame(fd,'E',registration.dump());
            registration["address"] = "0x2000";
            send_frame(fd,'E',registration.dump());
            registration["type"] = "jni_unregistration";
            send_frame(fd,'E',registration.dump());
            bool observed = false;
            for (int i=0; i<100; ++i) {
                auto state = g_jni_bindings.snapshot(pkg,"",100,true);
                if (state["count"] == 2 && state["bindings"][1]["binding_status"] == "unregistered") { observed=true; break; }
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
            assert(observed);
            httplib::Request query; httplib::Response response;
            query.params.emplace("package",pkg);
            handle_jni_bindings(query,response);
            auto state = json::parse(response.body);
            assert(state["mapping_version"] == 3 && state["bindings"][0]["binding_status"] == "superseded");
            assert(state["bindings"][0]["process"] == process && state["current_bindings_verified"] == false);
            registration["type"] = "jni_registration";
            registration["class_id"] = "loader-check";
            registration["address"] = "0x3100";
            registration["module"] = "/fixture.so";
            registration["observation_order"] = uint64_t(1);
            send_frame(fd, 'E', registration.dump());
            send_frame(fd, 'E', json({{"type", "native_library_unloaded"}, {"module", "/fixture.so"},
                {"executable_ranges", json::array({json::array({"0x3000", "0x3200"})})},
                {"observation_order", uint64_t(2)}}).dump());
            bool unloaded = false;
            for (int i = 0; i < 100; ++i) {
                auto state = g_jni_bindings.snapshot(pkg, "", 100, true);
                if (state["count"] == 3 && state["bindings"][2]["binding_status"] == "module_unloaded") { unloaded = true; break; }
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
            assert(unloaded);
        }
        shutdown(fd, SHUT_RDWR); close(fd); server.join();
        assert(runtime_status_snapshot(pkg)["processes"].empty());
        if (scenario == 0) assert(g_jni_bindings.snapshot(pkg,"",100,true)["bindings"][0]["runtime_connected"] == false);
    }
    std::filesystem::remove_all(directory);
    std::cout << "Native/Java IPC handshake and live config tests passed\n";
}

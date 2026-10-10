#pragma once
#include <deque>
#include <exception>
#include <functional>
#include "native_observation.h"

// Included by module.cpp: all engine mutation follows linker -> lifecycle ->
// per-ingress lock order. Bionic holds its recursive linker lock throughout a
// dl_iterate_phdr callback. Never wait for an application invocation under it.
template<class Operation> static void with_loader_lock(Operation operation) {
    struct Work { Operation& fn; std::exception_ptr failure; bool ran = false; } work{operation, {}, false};
    dl_iterate_phdr([](dl_phdr_info*, size_t, void* opaque) {
        auto& value = *static_cast<Work*>(opaque);
        value.ran = true;
        try { value.fn(); } catch (...) { value.failure = std::current_exception(); }
        return 1;
    }, &work);
    if (work.failure) std::rethrow_exception(work.failure);
    if (!work.ran) throw std::runtime_error("loader lock callback unavailable");
}

static std::deque<json> g_loader_events;
static uint64_t g_loader_dropped = 0;
static thread_local bool g_inside_loader_observer = false;

static std::string native_basename(const std::string& path) {
    return path.substr(path.find_last_of('/') == std::string::npos ? 0 : path.find_last_of('/') + 1);
}
static std::string native_hex(uintptr_t value) {
    char text[32]; snprintf(text, sizeof(text), "0x%llx", static_cast<unsigned long long>(value)); return text;
}
static std::vector<NativeLibrary> loaded_libraries() {
    std::vector<NativeLibrary> result;
    dl_iterate_phdr([](dl_phdr_info* info, size_t, void* data) {
        if (!info->dlpi_name || !*info->dlpi_name) return 0;
        NativeLibrary module; module.path = info->dlpi_name; module.base = info->dlpi_addr;
        for (size_t i = 0; i < info->dlpi_phnum; ++i) {
            const auto& header = info->dlpi_phdr[i];
            if (header.p_type != PT_LOAD || !(header.p_flags & PF_X) ||
                header.p_vaddr > UINTPTR_MAX - module.base) continue;
            const uintptr_t start = module.base + header.p_vaddr;
            if (header.p_memsz > UINTPTR_MAX - start) continue;
            module.executable.push_back({start, start + header.p_memsz});
        }
        static_cast<std::vector<NativeLibrary>*>(data)->push_back(std::move(module));
        return 0;
    }, &result);
    return result;
}
static void library_event(const NativeLibrary& module, const char* type, const char* source) {
    timespec ts{}; clock_gettime(CLOCK_REALTIME, &ts);
    json ranges = json::array();
    for (const auto& range : module.executable) ranges.push_back({native_hex(range.first), native_hex(range.second)});
    json event = {{"type", type}, {"kind", "native_loader"}, {"package", g_package},
        {"pid", getpid()}, {"process_instance", g_runtime_instance}, {"module", module.path},
        {"module_base", native_hex(module.base)}, {"library_generation", module.generation},
        {"executable_ranges", ranges}, {"source", source}, {"loader_seq", ++g_library_sequence},
        {"observation_order", module.retirement_order ? module.retirement_order : ++native_observation_sequence},
        {"ts", int64_t(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000}};
    if (g_loader_events.size() == 1024) { g_loader_events.pop_front(); ++g_loader_dropped; }
    g_loader_events.push_back(std::move(event));
}
static int retire_target(Target& target, const char* reason) {
    target.removal_requested = true;
    const int result = target.lifetime.remove([&] {
        if (!target.stub) return true;
        if (target.unhook_failed) return false; // ShadowHook may consume its handle even when unhook fails.
        if (!target.module_valid.load()) return false; // Never restore bytes into an unmapped/reused address.
#if defined(__aarch64__)
        const int rc = sh_unhook ? sh_unhook(target.stub) : -1;
        target.unhook_failed = rc != 0;
#else
        target.unhook_failed = !db_destroy || db_destroy(reinterpret_cast<void*>(target.address)) != 0;
#endif
        return !target.unhook_failed;
    });
    if (result == 1) {
        target.stub = nullptr;
        target.rearm_pending = true;
        g_native_status.lifecycle(target.status_key, "removed", {{"reason", reason}, {"physical_unhook", true}, {"slot_reclaimable", true}});
    } else {
        g_native_status.lifecycle(target.status_key, result == 0 ? "draining" : "unhook_failed",
            {{"reason", reason}, {"in_flight", target.lifetime.users()}, {"slot_reclaimable", false}});
    }
    return result;
}
static void library_removed(const NativeLibrary& module, const char* source) {
    // Include retired ingress guards: a delayed old branch must not call a new
    // image that happens to occupy its old address after dlclose/reload.
    for (auto& target : g_ingress_guards) {
        if (target->module_key != module.key() || target->library_generation != module.generation) continue;
        target->module_valid = false;
        if (!target->lifetime.removed()) {
            target->quarantined = true;
            g_native_status.lifecycle(target->status_key, "unloaded",
                {{"physical_unhook", false}, {"engine_handle_quarantined", target->stub != nullptr},
                 {"reason", "library_left_before_drain; never restore its old address"}});
        }
    }
    library_event(module, std::string(source) == "shadowhook_fini_pre" ? "native_library_unloading" : "native_library_unloaded", source);
}
static void sync_libraries(const char* source) {
    g_libraries.sync(loaded_libraries(),
        [&](const NativeLibrary& module) { library_removed(module, source); },
        [&](const NativeLibrary& module) { library_event(module, "native_library_loaded", source); });
}
static void prepare_native_target(size_t slot, const NativeSpec& spec) {
    auto target = std::make_shared<Target>();
    static_cast<NativeSpec&>(*target) = spec;
    target->slot = slot; target->generation = g_live.snapshot()->generations[slot] + 1;
    target->status_key = g_native_status.add({{"id", spec.id}, {"lib", spec.lib}, {"symbol", spec.symbol},
        {"offset", spec.has_offset ? json(spec.offset) : json(nullptr)}, {"slot", slot}, {"generation", target->generation}});
    g_slots[slot] = std::move(target);
}
static void install_native_target(const std::shared_ptr<Target>& target) {
    if (!g_native_status.pending(target->status_key)) return;
    const NativeLibrary* selected = nullptr;
    for (const auto& item : g_libraries.loaded()) if (native_basename(item.second.path) == target->lib) {
        if (selected) {
            g_native_status.lifecycle(target->status_key, "failed", {{"reason", "ambiguous_library_basename"}}); return;
        }
        selected = &item.second;
    }
    if (!selected) {
        target->poll_attempts = 0;
        g_native_status.lifecycle(target->status_key, "pending", {{"reason", "library_not_loaded"}});
        return;
    }
    uintptr_t address = 0;
    if (target->has_offset) {
        if (target->offset <= UINTPTR_MAX - selected->base) address = selected->base + target->offset;
    } else {
#if defined(__aarch64__)
        if (sh_open && sh_symbol && sh_close) {
            void* handle = sh_open(selected->path.c_str());
            if (handle) { address = reinterpret_cast<uintptr_t>(sh_symbol(handle, target->symbol.c_str())); sh_close(handle); }
        }
#else
        if (db_resolve) address = reinterpret_cast<uintptr_t>(db_resolve(selected->path.c_str(), target->symbol.c_str()));
#endif
    }
    if (!address) {
        if (target->poll_attempts.fetch_add(1) + 1 >= 200)
            g_native_status.lifecycle(target->status_key, "failed", {{"reason", "loaded_library_symbol_not_resolved"}, {"attempts", 200}});
        return;
    }
    if (!selected->contains(address)) {
        g_native_status.lifecycle(target->status_key, "failed", {{"reason", "resolved_address_outside_selected_executable_image"}}); return;
    }
    // A second selector must not own the same machine-code patch.
    for (const auto& other : g_slots) if (other && other != target && other->stub && other->address == address) {
        g_native_status.lifecycle(target->status_key, "failed", {{"reason", "address_already_managed"}}); return;
    }
    if (!target->gateway && g_ingress_guards.size() >= 4096) {
        g_native_status.lifecycle(target->status_key, "failed", {{"reason", "ingress_guard_capacity; restart_required"}}); return;
    }
    if (!target->gateway) {
        target->address = address; target->module_key = selected->key(); target->library_generation = selected->generation;
        target->gateway = native_gateway(target.get());
        g_ingress_guards.push_back(target);
    } else if (target->address != address || target->library_generation != selected->generation) {
        g_native_status.lifecycle(target->status_key, "failed", {{"reason", "image_identity_changed_during_rearm"}}); return;
    }
    target->lifetime.initialize([&] {
#if defined(__aarch64__)
        target->stub = sh_hook_sym_addr(reinterpret_cast<void*>(address), target->gateway, &target->orig);
        const int code = target->stub ? 0 : sh_get_errno();
#else
        const int code = db_hook(reinterpret_cast<void*>(address), target->gateway, &target->orig);
        if (!code) target->stub = reinterpret_cast<void*>(address);
#endif
        g_native_status.lifecycle(target->status_key, target->stub ? "installed" : "failed",
            {{"address", native_hex(address)}, {"code", code}, {"library_generation", selected->generation}});
        if (target->stub) { target->unhook_failed = false; target->removal_requested = false; }
        return target->stub != nullptr;
    });
}
static void reconcile_native_runtime() {
    sync_libraries("loader_snapshot");
    auto plan = g_live.snapshot();
    for (size_t slot = 0; slot < g_slots.size(); ++slot) {
        auto target = g_slots[slot];
        if (!target) continue;
        if (!plan->active[slot]) {
            if (target->quarantined || retire_target(*target, "configuration_removed") == 1) {
                if (g_live.release(slot, target->site_key())) {
                    g_native_status.history(target->status_key); g_slots[slot].reset();
                }
            }
            continue;
        }
        if (!target->module_valid.load()) {
            g_native_status.history(target->status_key);
            g_live.renew(slot, prepare_native_target); target = g_slots[slot];
        } else if (target->lifetime.removed() && target->rearm_pending) {
            target->rearm_pending = false;
            g_native_status.lifecycle(target->status_key, "pending", {{"reason", "image_survived_dlclose; reinstalling"}});
        } else if (target->stub && target->removal_requested && !target->unhook_failed) {
            target->removal_requested = false;
            g_native_status.lifecycle(target->status_key, "installed", {{"reason", "active_configuration_retained"},
                {"address", native_hex(target->address)}, {"library_generation", target->library_generation}});
        }
        install_native_target(target);
    }
}

#if defined(__aarch64__)
static void native_fini_pre(dl_phdr_info* info, size_t, void*) {
    if (!info->dlpi_name) return;
    try {
        std::lock_guard<std::recursive_mutex> lock(g_lifecycle_mutex);
        const std::string key = std::string(info->dlpi_name) + "\n" + std::to_string(info->dlpi_addr);
        for (auto& target : g_slots) if (target && target->module_key == key)
            retire_target(*target, "linker_fini");
        g_libraries.fini(info->dlpi_name, info->dlpi_addr, [&](const NativeLibrary& module) {
            library_removed(module, "shadowhook_fini_pre");
        }, ++native_observation_sequence);
    } catch (...) {}
}
static void native_init_post(dl_phdr_info* info, size_t, void*) {
    // Mark new generations immediately. The worker installs pending hooks after
    // linker returns; no socket writes or waits for app calls in this callback.
    try {
        std::lock_guard<std::recursive_mutex> lock(g_lifecycle_mutex);
        if (info->dlpi_name) g_libraries.arrived(info->dlpi_name, info->dlpi_addr,
            [&](const NativeLibrary& module) { library_removed(module, "reloaded_after_fini"); });
        sync_libraries("shadowhook_init_post");
    }
    catch (...) {}
}
#else
static int (*g_loader_close_original)(void*) = nullptr;
static int observe_loader_close(void* handle) {
    if (g_inside_loader_observer) return g_loader_close_original(handle);
    int result = -1, result_errno = errno;
    bool called = false;
    g_inside_loader_observer = true;
    try {
        with_loader_lock([&] {
            std::lock_guard<std::recursive_mutex> lock(g_lifecycle_mutex);
            sync_libraries("dlclose_before");
            // Dobby has no fini callback. Remove quiet managed patches BEFORE
            // dlclose can unmap any dependency. Busy ones are quarantined if the
            // image disappears; never write them back after unmapping.
            for (auto& target : g_slots) if (target && target->stub) retire_target(*target, "dlclose_barrier");
            g_inside_loader_observer = false; // Nested dlclose in destructors is a real observation.
            errno = result_errno;
            result = g_loader_close_original(handle); called = true; result_errno = errno;
            g_inside_loader_observer = true;
            sync_libraries("dlclose_after");
        });
    } catch (...) {
        if (!called) { errno = result_errno; result = g_loader_close_original(handle); result_errno = errno; }
    }
    g_inside_loader_observer = false;
    errno = result_errno;
    return result;
}
#endif

static void initialize_native_loader() {
    timespec ts{}; clock_gettime(CLOCK_MONOTONIC, &ts);
    g_runtime_instance = std::to_string(getpid()) + "-" + std::to_string(ts.tv_sec) + "-" + std::to_string(ts.tv_nsec);
    with_loader_lock([] {
        std::lock_guard<std::recursive_mutex> lock(g_lifecycle_mutex);
        sync_libraries("initial_snapshot");
#if defined(__aarch64__)
        const int fini = sh_reg_dl_fini ? sh_reg_dl_fini(native_fini_pre, nullptr, nullptr) : -1;
        const int init = sh_reg_dl_init ? sh_reg_dl_init(nullptr, native_init_post, nullptr) : -1;
        g_loader_status = {{"status", fini == 0 && init == 0 ? "installed" : "partial"},
            {"continuous", fini == 0}, {"mechanism", "shadowhook_linker_fini_init"}, {"fini_code", fini}, {"init_code", init}};
#else
        void* close = dlsym(RTLD_DEFAULT, "__loader_dlclose");
        if (!close && db_resolve) close = db_resolve("linker64", "__loader_dlclose");
        const int code = close && db_destroy ? db_hook(close, reinterpret_cast<void*>(observe_loader_close),
            reinterpret_cast<void**>(&g_loader_close_original)) : -1;
        g_loader_status = {{"status", code == 0 ? "installed" : "unavailable"}, {"continuous", code == 0},
            {"mechanism", "bionic_dlclose_before_after"}, {"code", code}};
#endif
        g_loader_status["snapshot_interval_ms"] = 150;
        g_loader_status["scope"] = "linker managed images; raw munmap/custom loaders excluded";
    });
}
static void start_native_worker() {
    std::thread([] {
        for (;;) {
            usleep(150000);
            std::deque<json> events;
            try {
                with_loader_lock([&] {
                    std::lock_guard<std::recursive_mutex> lock(g_lifecycle_mutex);
                    g_inside_loader_observer = true;
                    try { reconcile_native_runtime(); } catch (...) { g_inside_loader_observer = false; throw; }
                    g_inside_loader_observer = false;
                    events.swap(g_loader_events);
                    g_loader_status["events_dropped"] = g_loader_dropped;
                });
                for (const auto& event : events) send_event(event.dump(-1, ' ', false, json::error_handler_t::replace));
                publish_native_status();
            } catch (...) { /* Retry maintenance without unwinding an app thread. */ }
        }
    }).detach();
}

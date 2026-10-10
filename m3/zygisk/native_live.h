#pragma once
#include "third_party/json.hpp"
#include <atomic>
#include <array>
#include <cerrno>
#include <cstdlib>
#include <cmath>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

enum ArgType { T_INT, T_PTR, T_STR, T_BYTES, T_FLOAT, T_DOUBLE, T_VOID };
enum ActionType { ACT_OBSERVE, ACT_REPLACE_RET, ACT_REPLACE_ARG };

struct ArgSpec {
    int index = 0;
    ArgType type = T_INT;
    int len = -1;       // bytes 固定长度
    int len_from = -1;  // bytes 长度取自第 N 个参数
    int max = 256;      // string 最长
};

struct NativeSpec {
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
    int64_t dump_size_fixed = -1;  // 固定长度（与 size_arg 二选一）
    int dump_max = 32 * 1024 * 1024;  // 单次上限 32MB
    std::string dump_ext = "bin";
    ActionType action = ACT_OBSERVE;
    int64_t ret_value = 0;
    std::vector<std::pair<int, int64_t>> arg_overrides;
    bool explicit_signature = false;
    size_t signature_count = 8;
    std::array<ArgType, 8> signature_args{};  // legacy: eight machine-word integers
    ArgType signature_ret = T_INT;
    double fp_ret_value = 0;
    std::vector<std::pair<int, double>> fp_arg_overrides;
    size_t config_index = 0;
    nlohmann::json requested;
    std::string site_key() const {
        return lib + "\n" + (has_offset ? "offset:" + std::to_string(offset) : "symbol:" + symbol);
    }
    std::string abi_key() const {
        std::string key = std::to_string(signature_ret);
        for (size_t i = 0; i < signature_count; ++i) key += ":" + std::to_string(signature_args[i]);
        return key;
    }
};

inline ArgType parse_type(const std::string& s) {
    if (s == "ptr") return T_PTR;
    if (s == "string") return T_STR;
    if (s == "bytes") return T_BYTES;
    if (s == "int") return T_INT;
    if (s == "float") return T_FLOAT;
    if (s == "double") return T_DOUBLE;
    throw std::invalid_argument("unsupported native capture type: " + s);
}

inline bool native_floating(ArgType type) { return type == T_FLOAT || type == T_DOUBLE; }
inline ArgType parse_abi_type(const std::string& type, bool result = false) {
    if (type == "int" || type == "int64") return T_INT;
    if (type == "ptr") return T_PTR;
    if (type == "float") return T_FLOAT;
    if (type == "double") return T_DOUBLE;
    if (result && type == "void") return T_VOID;
    throw std::invalid_argument("unsupported scalar native ABI type: " + type);
}
inline double native_fp_config(const nlohmann::json& value, ArgType type) {
    if (!value.is_number()) throw std::invalid_argument("floating replacement must be numeric");
    const double number = value.get<double>();
    if (!std::isfinite(number) || (type == T_FLOAT && std::abs(number) > std::numeric_limits<float>::max()))
        throw std::invalid_argument("floating replacement must be finite and representable");
    return number;
}
inline uint64_t native_fp_bits(ArgType type, double value) {
    uint64_t bits = 0;
    if (type == T_FLOAT) {
        const float rounded = static_cast<float>(value);
        std::memcpy(&bits, &rounded, sizeof(rounded));
    } else std::memcpy(&bits, &value, sizeof(value));
    return bits;
}

inline NativeSpec parse_native_spec(const nlohmann::json& jt, size_t ordinal) {
    NativeSpec t;
    t.config_index = ordinal;
    t.requested = jt;
    if (!jt.is_object()) throw std::invalid_argument("target must be an object");
    if (jt.contains("kind") && !jt["kind"].is_string())
        throw std::invalid_argument("kind must be a string");
    t.id = jt.value("id", "h" + std::to_string(ordinal));
    t.lib = jt.value("lib", "");
    t.symbol = jt.value("symbol", "");
    t.has_offset = jt.contains("offset");
    if (t.lib.empty() || t.lib.find('/') != std::string::npos)
        throw std::invalid_argument("lib must be a nonempty basename");
    if (t.has_offset == !t.symbol.empty())
        throw std::invalid_argument("specify exactly one of symbol or offset");
    if (t.has_offset) {
        if (jt["offset"].is_string()) {
            const auto value = jt["offset"].get<std::string>();
            char* tail = nullptr;
            errno = 0;
            t.offset = strtoull(value.c_str(), &tail, value.rfind("0x", 0) == 0 ? 16 : 10);
            if (value.empty() || value[0] == '-' || value[0] == '+' ||
                (value[0] < '0' || value[0] > '9') || errno || tail != value.c_str() + value.size())
                throw std::invalid_argument("invalid offset");
        } else {
            if (!jt["offset"].is_number_integer() || jt["offset"] < 0)
                throw std::invalid_argument("offset must be a nonnegative integer");
            t.offset = jt["offset"].get<uint64_t>();
        }
    }
    if (jt.contains("signature")) {
        const auto& sig = jt["signature"];
        if (!sig.is_object() || !sig.contains("args") || !sig["args"].is_array() ||
            sig["args"].size() > 8 || !sig.contains("ret") || !sig["ret"].is_string())
            throw std::invalid_argument("signature requires args (0..8 scalar types) and ret");
        if (sig.value("variadic", false)) throw std::invalid_argument("variadic native ABI is unsupported");
        t.explicit_signature = true;
        t.signature_count = sig["args"].size();
        for (size_t i = 0; i < t.signature_count; ++i)
            t.signature_args[i] = parse_abi_type(sig["args"][i].get<std::string>());
        t.signature_ret = parse_abi_type(sig["ret"].get<std::string>(), true);
    }
    // capture
    if (jt.contains("capture")) {
        auto& cap = jt["capture"];
        if (!cap.is_object() || (cap.contains("args") && !cap["args"].is_array()))
            throw std::invalid_argument("capture must be an object; args must be an array");
        if (cap.contains("args") && cap["args"].is_array()) {
            for (auto& ja : cap["args"]) {
                ArgSpec s;
                s.index = ja.value("index", 0);
                s.type = parse_type(ja.value("type", std::string("int")));
                s.len = ja.value("len", -1);
                s.len_from = ja.value("len_from", -1);
                s.max = ja.value("max", 256);
                if (s.index < 0 || s.index > 7 || s.len_from < -1 || s.len_from > 7 || s.max < 0 || s.max > 65536)
                    throw std::invalid_argument("invalid native argument index or capture bound");
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
            t.dump_size_fixed = dp.value("size", int64_t(-1));
            t.dump_max = dp.value("max", 32 * 1024 * 1024);
            t.dump_ext = dp.value("ext", std::string("bin"));
            if (t.dump_base_arg < 0 || t.dump_base_arg > 7 || t.dump_size_arg < -1 || t.dump_size_arg > 7 ||
                t.dump_max < 0 || t.dump_max > 32 * 1024 * 1024)
                throw std::invalid_argument("invalid dump bounds");
        }
    }
    // action
    if (jt.contains("action")) {
        auto& ac = jt["action"];
        std::string at = ac.value("type", std::string("observe"));
        if (at != "observe" && at != "replace_ret" && at != "replace_arg")
            throw std::invalid_argument("unsupported native action");
        t.action = (at == "replace_ret") ? ACT_REPLACE_RET : (at == "replace_arg") ? ACT_REPLACE_ARG : ACT_OBSERVE;
        if (ac.contains("ret_value")) {
            if (native_floating(t.signature_ret)) t.fp_ret_value = native_fp_config(ac["ret_value"], t.signature_ret);
            else {
                if (!ac["ret_value"].is_number_integer()) throw std::invalid_argument("ret_value must be an integer (declare signature for floating return)");
                t.ret_value = ac["ret_value"].get<int64_t>();
            }
        }
        if (ac.contains("arg_overrides") && !ac["arg_overrides"].is_array())
            throw std::invalid_argument("arg_overrides must be an array");
        if (ac.contains("arg_overrides") && ac["arg_overrides"].is_array())
            for (auto& ov : ac["arg_overrides"]) {
                const int index = ov.value("index", 0);
                if (index < 0 || size_t(index) >= t.signature_count || !ov.contains("value"))
                    throw std::invalid_argument("invalid native argument override");
                if (native_floating(t.signature_args[index]))
                    t.fp_arg_overrides.push_back({index, native_fp_config(ov["value"], t.signature_args[index])});
                else {
                    if (!ov["value"].is_number_integer()) throw std::invalid_argument("integer argument requires an integer replacement");
                    t.arg_overrides.push_back({index, ov["value"].get<int64_t>()});
                }
            }
    }
    auto integer_arg = [&](int index) {
        return index >= 0 && size_t(index) < t.signature_count && !native_floating(t.signature_args[index]);
    };
    for (const auto& arg : t.args) {
        if (size_t(arg.index) >= t.signature_count ||
            (native_floating(arg.type) ? (!t.explicit_signature || arg.type != t.signature_args[arg.index])
                                       : native_floating(t.signature_args[arg.index])))
            throw std::invalid_argument("capture type/index does not match complete native signature");
        if (arg.len_from >= 0 && !integer_arg(arg.len_from))
            throw std::invalid_argument("capture len_from must refer to an integer argument");
    }
    if (t.cap_ret && (t.signature_ret == T_VOID ||
        (native_floating(t.ret_type) ? (!t.explicit_signature || t.ret_type != t.signature_ret)
                                    : native_floating(t.signature_ret))))
        throw std::invalid_argument("return capture does not match native signature");
    if (t.action == ACT_REPLACE_RET && t.signature_ret == T_VOID)
        throw std::invalid_argument("cannot replace a void return");
    if (t.has_dump && (!integer_arg(t.dump_base_arg) ||
        (t.dump_size_fixed < 0 && !integer_arg(t.dump_size_arg))))
        throw std::invalid_argument("dump pointers/lengths require integer-class arguments");
    if (t.id.empty()) throw std::invalid_argument("native id cannot be empty");
    for (const auto* value : {&t.id, &t.lib, &t.symbol})
        if (value->find('\0') != std::string::npos || value->find('\n') != std::string::npos)
            throw std::invalid_argument("native identifiers cannot contain NUL/newline");
    return t;
}

// A proxy takes ONE immutable snapshot per invocation. Removing/replacing a
// hook changes future invocations; in-flight invocations own their old config.
// Slots are released only after the runtime confirms physical removal. Each
// allocation has a generation; a delayed old gateway cannot adopt a reused slot.
class NativeLiveRegistry {
public:
    static constexpr size_t capacity = 64;
    struct Plan {
        uint64_t revision = 0;
        std::array<std::shared_ptr<const NativeSpec>, capacity> active{};
        std::array<uint64_t, capacity> generations{};
        nlohmann::json desired = nlohmann::json::array();
    };
    struct Added { size_t slot; std::shared_ptr<const NativeSpec> spec; };
    struct Change { std::shared_ptr<const Plan> plan; std::vector<Added> added; bool changed; };
private:
    mutable std::mutex writer_;
    std::unordered_map<std::string, size_t> sites_;
    std::unordered_map<std::string, std::string> signatures_;
    std::shared_ptr<const Plan> plan_ = std::make_shared<const Plan>();
    std::array<uint64_t, capacity> generations_{};
public:
    std::shared_ptr<const Plan> snapshot() const { return std::atomic_load(&plan_); }
    bool release(size_t slot, const std::string& site) {
        std::lock_guard<std::mutex> lock(writer_);
        const auto found = sites_.find(site);
        if (found == sites_.end() || found->second != slot || snapshot()->active.at(slot)) return false;
        sites_.erase(found); signatures_.erase(site);
        return true;
    }
    template<class Prepare> void renew(size_t slot, Prepare prepare) {
        std::lock_guard<std::mutex> lock(writer_);
        auto previous = snapshot();
        if (!previous->active.at(slot)) throw std::logic_error("cannot renew an inactive slot");
        auto next = std::make_shared<Plan>(*previous);
        prepare(slot, *previous->active[slot]);
        next->generations[slot] = ++generations_[slot];
        std::shared_ptr<const Plan> committed = next;
        std::atomic_store(&plan_, committed);
    }
    template<class PrepareSlot>
    Change reconcile(const nlohmann::json& cfg, PrepareSlot prepare_slot) {
        using json = nlohmann::json;
        if (!cfg.is_object() || !cfg.contains("targets") || !cfg["targets"].is_array())
            throw std::invalid_argument("targets must be an array");
        std::vector<std::shared_ptr<const NativeSpec>> specs;
        std::set<std::string> ids, selectors;
        json desired = json::array();
        for (size_t i = 0; i < cfg["targets"].size(); ++i) {
            const auto& target = cfg["targets"][i];
            if (!target.is_object()) throw std::invalid_argument("target must be an object");
            const auto kind = target.value("kind", std::string("native"));
            if (kind != "native") continue;
            auto spec = std::make_shared<const NativeSpec>(parse_native_spec(target, i));
            if (!ids.insert(spec->id).second) throw std::invalid_argument("duplicate native id: " + spec->id);
            if (!selectors.insert(spec->site_key()).second) throw std::invalid_argument("duplicate native hook point");
            desired.push_back(target);
            specs.push_back(std::move(spec));
        }
        std::lock_guard<std::mutex> lock(writer_);
        auto previous = snapshot();
        if (desired == previous->desired) return {previous, {}, false};
        auto sites = sites_;
        auto signatures = signatures_;
        auto next = std::make_shared<Plan>();
        auto generations = generations_;
        next->revision = previous->revision + 1;
        next->desired = std::move(desired);
        std::vector<Added> added;
        for (auto& spec : specs) {
            auto found = sites.find(spec->site_key());
            size_t slot;
            if (found != sites.end()) {
                if (signatures.at(spec->site_key()) != spec->abi_key())
                    throw std::invalid_argument("cannot change ABI of a retained native point; restart required");
                slot = found->second;
            }
            else {
                if (sites.size() >= capacity) throw std::invalid_argument("native slots full; wait for physical removal/drain before retrying");
                std::array<bool, capacity> used{};
                for (const auto& pair : sites) used[pair.second] = true;
                slot = 0; while (used[slot]) ++slot;
                ++generations[slot];
                sites[spec->site_key()] = slot;
                signatures[spec->site_key()] = spec->abi_key();
                added.push_back({slot, spec});
            }
            next->active[slot] = spec;
        }
        next->generations = generations;
        // Validate the complete transaction before publishing any slot/config.
        for (const auto& item : added) prepare_slot(item.slot, *item.spec);
        sites_ = std::move(sites);
        signatures_ = std::move(signatures);
        generations_ = generations;
        std::shared_ptr<const Plan> committed = next;
        std::atomic_store(&plan_, committed);
        return {committed, std::move(added), true};
    }
};

template<class Original, class Emit>
long invoke_native(const NativeLiveRegistry& registry, size_t slot,
                   std::array<long, 8> args, Original original, Emit emit, uint64_t generation = 0) {
    auto plan = registry.snapshot();
    const auto spec = !generation || plan->generations.at(slot) == generation ? plan->active.at(slot) : nullptr;
    if (!spec) return original(args);
    if (spec->action == ACT_REPLACE_ARG)
        for (const auto& override : spec->arg_overrides) args[override.first] = override.second;
    if (spec->action == ACT_REPLACE_ARG)
        for (const auto& override : spec->fp_arg_overrides)
            args[override.first] = static_cast<long>(native_fp_bits(spec->signature_args[override.first], override.second));
    const long result = original(args);
    emit(*spec, plan->revision, args, result);
    if (spec->action != ACT_REPLACE_RET) return result;
    return native_floating(spec->signature_ret)
        ? static_cast<long>(native_fp_bits(spec->signature_ret, spec->fp_ret_value)) : spec->ret_value;
}

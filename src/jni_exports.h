#pragma once
#include "third_party/json.hpp"
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>
#include <stdexcept>

namespace reconbridge {
using JniJson = nlohmann::json;
inline std::string jni_unescape(const std::string& text) {
    std::vector<uint16_t> units;
    for (size_t i = 0; i < text.size();) {
        unsigned char c = text[i++];
        if (c != '_') {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')))
                throw std::invalid_argument("invalid JNI name");
            units.push_back(c); continue;
        }
        if (i < text.size() && text[i] >= '1' && text[i] <= '3') {
            units.push_back(text[i] == '1' ? '_' : text[i] == '2' ? ';' : '['); ++i;
        } else if (i < text.size() && text[i] == '0') {
            if (text.size() - i < 5) throw std::invalid_argument("short JNI escape");
            uint16_t value = 0; ++i;
            for (int n = 0; n < 4; ++n) {
                char h = text[i++];
                if (!((h >= '0' && h <= '9') || (h >= 'a' && h <= 'f'))) throw std::invalid_argument("invalid JNI escape");
                value = uint16_t(value * 16 + (h <= '9' ? h - '0' : h - 'a' + 10));
            }
            if (!value) throw std::invalid_argument("NUL in JNI name");
            units.push_back(value);
        } else units.push_back('/');
    }
    std::string out;
    for (size_t i = 0; i < units.size(); ++i) {
        uint32_t cp = units[i];
        if (cp >= 0xd800 && cp <= 0xdbff) {
            if (++i == units.size() || units[i] < 0xdc00 || units[i] > 0xdfff) throw std::invalid_argument("invalid surrogate pair");
            cp = 0x10000 + ((cp - 0xd800) << 10) + units[i] - 0xdc00;
        } else if (cp >= 0xdc00 && cp <= 0xdfff) throw std::invalid_argument("unpaired surrogate");
        if (cp < 0x80) out += char(cp);
        else if (cp < 0x800) { out += char(0xc0 | (cp >> 6)); out += char(0x80 | (cp & 63)); }
        else if (cp < 0x10000) {
            out += char(0xe0 | (cp >> 12)); out += char(0x80 | ((cp >> 6) & 63)); out += char(0x80 | (cp & 63));
        } else {
            out += char(0xf0 | (cp >> 18)); out += char(0x80 | ((cp >> 12) & 63));
            out += char(0x80 | ((cp >> 6) & 63)); out += char(0x80 | (cp & 63));
        }
    }
    return out;
}
inline JniJson decode_jni_export(const std::string& symbol) {
    if (symbol.rfind("Java_", 0) != 0) throw std::invalid_argument("not a JNI export");
    auto name = symbol.substr(5);
    size_t split = std::string::npos, overload = std::string::npos;
    // Consume escapes before considering separators (_1 can occur in method names).
    for (size_t i = 0; i < name.size();) {
        if (name[i] != '_') { ++i; continue; }
        if (i + 1 < name.size() && name[i + 1] == '_') { overload = i; break; }
        if (i + 1 < name.size() && name[i + 1] >= '0' && name[i + 1] <= '3')
            i += name[i + 1] == '0' ? 6 : 2;
        else { split = i; ++i; }
    }
    const auto end = overload == std::string::npos ? name.size() : overload;
    if (split == std::string::npos || split == 0 || split + 1 >= end) throw std::invalid_argument("missing class/method");
    auto clazz = jni_unescape(name.substr(0, split));
    for (auto& c : clazz) if (c == '/') c = '.';
    const auto method = jni_unescape(name.substr(split + 1, end - split - 1));
    return {{"class", clazz}, {"method", method}, {"signature", nullptr},
        {"parameter_descriptor", overload == std::string::npos ? JniJson(nullptr) : JniJson(jni_unescape(name.substr(overload + 2)))},
        {"overloaded_name", overload != std::string::npos}, {"return_type_known", false}};
}

// Read-only bounded ELF64 little-endian dynamic export inspection. Never dlopen
// the file. Sectionless/extended-index files are explicitly unsupported.
class JniElf {
    const std::vector<uint8_t>& bytes_;
public:
    explicit JniElf(const std::vector<uint8_t>& bytes) : bytes_(bytes) {}
    void range(uint64_t offset, uint64_t size) const {
        if (offset > bytes_.size() || size > bytes_.size() - offset) throw std::invalid_argument("ELF range outside file");
    }
    uint64_t number(uint64_t offset, size_t size) const {
        range(offset, size); uint64_t value = 0;
        for (size_t i = 0; i < size; ++i) value |= uint64_t(bytes_[offset + i]) << (8 * i);
        return value;
    }
    std::string string(uint64_t offset, uint64_t length) const {
        range(offset, length);
        std::string value;
        for (uint64_t i = 0; i < length && i <= 8192; ++i) {
            if (!bytes_[offset + i]) return value;
            value += char(bytes_[offset + i]);
        }
        throw std::invalid_argument("unterminated/oversized ELF symbol");
    }
    JniJson exports(const std::string& filter, size_t limit) const {
        range(0, 64);
        if (number(0,4) != 0x464c457f || number(4,1) != 2 || number(5,1) != 1 || number(6,1) != 1)
            throw std::invalid_argument("requires ELF64 little-endian v1");
        const auto type = number(16,2), machine = number(18,2);
        if (type != 3 || (machine != 183 && machine != 62)) throw std::invalid_argument("requires ARM64/x86_64 shared ELF");
        const auto sections = number(40,8), entry_size = number(58,2), count = number(60,2);
        if (!sections || entry_size != 64 || !count) throw std::invalid_argument("sectionless/extended ELF not supported");
        range(sections, count * 64);
        JniJson exports = JniJson::array();
        size_t available = 0, invalid_names = 0, inspected = 0;
        bool dynamic_symbols = false;
        for (uint64_t i = 0; i < count; ++i) {
            const auto sh = sections + i * 64;
            if (number(sh + 4,4) != 11) continue; // SHT_DYNSYM, not debug .symtab
            dynamic_symbols = true;
            const auto offset = number(sh + 24,8), size = number(sh + 32,8), link = number(sh + 40,4);
            if (number(sh + 56,8) != 24 || size % 24 || link >= count) throw std::invalid_argument("invalid dynsym table");
            range(offset,size);
            const auto strsh = sections + link * 64;
            if (number(strsh + 4,4) != 3) throw std::invalid_argument("invalid dynsym string table");
            const auto strings = number(strsh + 24,8), strings_size = number(strsh + 32,8);
            range(strings,strings_size);
            if (size / 24 > 1000000 - inspected) throw std::invalid_argument("ELF symbol budget exceeded");
            inspected += size / 24;
            for (uint64_t sym = offset; sym < offset + size; sym += 24) {
                const auto info = number(sym + 4,1), visibility = number(sym + 5,1) & 3;
                if ((info >> 4 != 1 && info >> 4 != 2) || ((info & 15) != 2 && (info & 15) != 10) ||
                    (visibility != 0 && visibility != 3) || number(sym + 6,2) == 0) continue;
                const auto index = number(sym,4);
                if (index >= strings_size) throw std::invalid_argument("invalid symbol string offset");
                const auto name = string(strings + index, strings_size - index);
                if (name.rfind("Java_",0) != 0) continue;
                JniJson row;
                try { row = decode_jni_export(name); }
                catch (const std::invalid_argument&) { ++invalid_names; continue; }
                if (row["class"].get<std::string>().find(filter) == std::string::npos) continue;
                ++available;
                if (exports.size() >= limit) continue;
                char value[32]; std::snprintf(value,sizeof(value),"0x%llx",(unsigned long long)number(sym + 8,8));
                row.update(JniJson({{"symbol",name}, {"elf_value",value}, {"source","ELF.dynsym"},
                    {"binding_status","export_candidate"}, {"current_binding_verified",false},
                    {"symbol_kind",(info & 15) == 10 ? "ifunc_resolver" : "function"}}));
                exports.push_back(std::move(row));
            }
        }
        return {{"exports",exports}, {"count",exports.size()}, {"available",available},
            {"result_truncated",available > limit}, {"invalid_jni_names",invalid_names},
            {"dynamic_symbols_found",dynamic_symbols}, {"machine",machine},
            {"current_bindings_verified",false},
            {"coverage","file exports only; no load/binding proof; return types absent; elf_value is relative to ELF load bias, not file offset"}};
    }
};
inline JniJson inspect_jni_elf(const std::string& path, const std::string& filter, size_t limit) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) throw std::invalid_argument("cannot open ELF file");
    const auto size = file.tellg();
    if (size < 0 || size > 128 * 1024 * 1024) throw std::invalid_argument("ELF file exceeds 128 MiB limit");
    std::vector<uint8_t> bytes(static_cast<size_t>(size));
    file.seekg(0);
    if (!file.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size())))
        throw std::invalid_argument("cannot read complete ELF file");
    auto result = JniElf(bytes).exports(filter,limit);
    result["path"] = path;
    return result;
}
} // namespace reconbridge

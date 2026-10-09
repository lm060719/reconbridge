#pragma once
#include <sstream>
#include <string>
#include <cstdint>

namespace reconbridge {
inline std::string jni_address_mapping(const std::string& address, const std::string& module, const std::string& maps) {
    if (address.rfind("0x",0) != 0 || address.size() <= 2 || address.size() > 18) return "unknown";
    uint64_t pointer = 0;
    for (size_t i = 2; i < address.size(); ++i) {
        char c = address[i];
        int digit = c >= '0' && c <= '9' ? c-'0' : c >= 'a' && c <= 'f' ? c-'a'+10 : c >= 'A' && c <= 'F' ? c-'A'+10 : -1;
        if (digit < 0) return "unknown";
        pointer = pointer * 16 + digit;
    }
    std::istringstream input(maps); std::string line;
    bool any = false;
    while (std::getline(input,line)) {
        std::istringstream row(line);
        uint64_t start, end; char dash;
        std::string permissions, offset, device, inode, path;
        if (!(row >> std::hex >> start >> dash >> end >> permissions >> offset >> device >> inode) || dash != '-' || end <= start)
            return "unknown";
        any = true;
        if (pointer < start || pointer >= end) continue;
        std::getline(row,path); const auto begin = path.find_first_not_of(' ');
        path = begin == std::string::npos ? "" : path.substr(begin);
        if (permissions.find('x') == std::string::npos) return "not_executable";
        if (module.empty()) return "mapped_identity_unknown";
        if (path == module) return "mapped";
        if (path == module + " (deleted)") return "mapped_file_deleted";
        return "module_path_mismatch";
    }
    return any ? "not_mapped" : "unknown";
}
} // namespace reconbridge

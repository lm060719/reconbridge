#pragma once
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <sys/mman.h>
#include <unistd.h>

extern "C" void rb_native_entry();

// An immutable per-installation ingress. Unlike a reused proxy_0, a thread that
// already branched here can never acquire a different slot owner's signature.
// Keep this small RX page and its context until process exit (bounded by caller).
inline void* native_gateway(void* context) {
    const size_t size = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    auto* page = static_cast<unsigned char*>(mmap(nullptr, size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (page == MAP_FAILED) throw std::runtime_error("native gateway mmap failed");
    const uintptr_t target = reinterpret_cast<uintptr_t>(&rb_native_entry);
    const uintptr_t argument = reinterpret_cast<uintptr_t>(context);
#if defined(__aarch64__)
    // BTI c; ldr x16, literal(context); ldr x17, literal(entry); br x17.
    const uint32_t code[] = {0xd503245f, 0x58000070, 0x58000091, 0xd61f0220};
    std::memcpy(page, code, sizeof(code));
    std::memcpy(page + 16, &argument, 8); std::memcpy(page + 24, &target, 8);
#elif defined(__x86_64__)
    const unsigned char code[] = {0xf3,0x0f,0x1e,0xfa,0x49,0xba,0,0,0,0,0,0,0,0,
        0x49,0xbb,0,0,0,0,0,0,0,0,0x41,0xff,0xe3};
    std::memcpy(page, code, sizeof(code));
    std::memcpy(page + 6, &argument, 8); std::memcpy(page + 16, &target, 8);
#else
#error Unsupported native gateway architecture
#endif
    __builtin___clear_cache(reinterpret_cast<char*>(page), reinterpret_cast<char*>(page + 32));
    if (mprotect(page, size, PROT_READ | PROT_EXEC)) {
        munmap(page, size); throw std::runtime_error("native gateway mprotect RX failed");
    }
    return page;
}

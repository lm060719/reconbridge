#pragma once
#include <atomic>
#include <cstdint>
// Shared by JNI and loader observations. Delivery can be delayed independently;
// an old queued unload must never invalidate a newer registration at that address.
inline std::atomic<uint64_t> native_observation_sequence{0};

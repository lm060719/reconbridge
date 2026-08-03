#pragma once

#include <string>

#include "third_party/httplib.h"

namespace mobile_mcp {

// Allow the public artifact route to use a short-lived, file-scoped bearer
// token instead of exposing the daemon-wide MCP token to a rootfs shell.
bool authorize_artifact_request(const httplib::Request& request);

// Register the Streamable HTTP MCP endpoint on a loopback-only server. The
// same server also carries the existing REST routes for internal dispatch.
void register_routes(httplib::Server& server, const std::string& base_dir,
                     int public_port, int internal_port,
                     const std::string& token);

}  // namespace mobile_mcp

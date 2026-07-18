// M3 动态子系统：/hook /unhook /hooks + SSE/WS 事件推流。
// 与 M1 静态守护进程解耦：daemon.cpp 在建服务器/起停时调用这里的接口。
#pragma once
#include <string>
#include "third_party/httplib.h"

namespace dynamic {

// 初始化（进程启动时调用一次）。base_dir = 运行目录（如 /data/adb/reconbridge）。
// 启动 events.log 监听线程 + 事件广播器。
void init(const std::string& base_dir);

// 在每次新建 httplib::Server 时调用，注册 /hook /unhook /hooks /events(SSE) 路由。
void register_routes(httplib::Server& svr);

// HTTP 服务开始监听时调用：在 http_port+1 起一个极简 WS 服务（/events）。
void on_server_start(const std::string& host, int http_port);
// HTTP 服务停止时调用：关掉 WS 服务。
void on_server_stop();

}  // namespace dynamic

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

// A stdio MCP server for test-plugins to start through the mcp plugin:
// line-delimited JSON-RPC on stdin and stdout, a line of noise on each, and
// tools that exercise what the plugin does with them.
//
//   echo         read-only; pings the client first, then returns its
//                arguments and FAKE_TOKEN from its environment
//   write        no annotations, so it counts as writing
//   image        a PNG and a JPEG
//   fail         isError
//   slow         answers nothing, and goes on when the client cancels it
//   exit         exits without answering
//   dotted.name  a name the plugin must make fit
//
// The list comes in two pages. FAKE_MCP_VERSION, when set, is the protocol
// version it claims.

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>

#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace {

void send(const json& m) {
    std::cout << m.dump() << "\n";
    std::cout.flush();
}

std::string env(const char* name) {
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
    const char* v = std::getenv(name);
#ifdef _MSC_VER
#pragma warning(pop)
#endif
    return v ? v : "";
}

json text(const std::string& s) {
    return {{"content", json::array({{{"type", "text"}, {"text", s}}})}};
}

json tool(const std::string& name, bool read_only, json schema = {{"type", "object"}}) {
    json t = {{"name", name}, {"description", "The " + name + " tool."}, {"inputSchema", schema}};
    if (read_only) t["annotations"] = {{"readOnlyHint", true}};
    return t;
}

} // namespace

int main() {
    std::cerr << "fake server starting" << std::endl;
    std::cout << "this line is not JSON" << std::endl;

    std::string line;
    while (std::getline(std::cin, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const json m = json::parse(line, nullptr, false);
        if (m.is_discarded() || !m.contains("method")) continue;
        const std::string method = m["method"];
        if (!m.contains("id")) continue; // notifications
        const json id = m["id"];
        const json params = m.value("params", json::object());
        auto reply = [&](const json& result) {
            send({{"jsonrpc", "2.0"}, {"id", id}, {"result", result}});
        };

        if (method == "initialize") {
            const std::string forced = env("FAKE_MCP_VERSION");
            reply({{"protocolVersion", forced.empty() ? params.value("protocolVersion", "") : forced},
                   {"capabilities", {{"tools", json::object()}}},
                   {"serverInfo", {{"name", "fake"}, {"version", "1"}}}});
        } else if (method == "tools/list") {
            if (!params.contains("cursor")) {
                const json schema = json::parse(R"({
                  "$schema": "http://json-schema.org/draft-07/schema#",
                  "type": "object",
                  "properties": {
                    "text": {"type": ["string", "null"], "description": "What to echo."},
                    "opt": {"$ref": "#/$defs/Opt"}
                  },
                  "required": ["text"],
                  "additionalProperties": false,
                  "$defs": {"Opt": {"type": "object", "properties": {"n": {"type": "integer"}},
                                    "additionalProperties": false}}
                })");
                reply({{"tools", json::array({tool("echo", true, schema), tool("write", false)})},
                       {"nextCursor", "2"}});
            } else {
                reply({{"tools", json::array({tool("image", true), tool("fail", true),
                                              tool("slow", true), tool("exit", true),
                                              tool("dotted.name", true)})}});
            }
        } else if (method == "tools/call") {
            const std::string name = params.value("name", "");
            const json args = params.value("arguments", json::object());
            if (name == "echo") {
                // A request of its own first: the client must answer it.
                send({{"jsonrpc", "2.0"}, {"id", "srv-1"}, {"method", "ping"}});
                std::string answer;
                bool pinged = false;
                while (std::getline(std::cin, answer)) {
                    const json a = json::parse(answer, nullptr, false);
                    if (!a.is_discarded() && a.value("id", json()) == "srv-1") {
                        pinged = a.contains("result");
                        break;
                    }
                }
                reply(text("echo " + args.dump() + " token=" + env("FAKE_TOKEN") +
                           (pinged ? " pinged" : " not pinged")));
            } else if (name == "write") {
                reply(text("wrote"));
            } else if (name == "image") {
                reply({{"content",
                        json::array(
                            {{{"type", "image"},
                              {"mimeType", "image/png"},
                              {"data", "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg=="}},
                             {{"type", "image"}, {"mimeType", "image/jpeg"}, {"data", "/9j/AA=="}}})}});
            } else if (name == "fail") {
                json r = text("it broke");
                r["isError"] = true;
                reply(r);
            } else if (name == "slow") {
                std::string next;
                bool told = false;
                while (!told && std::getline(std::cin, next)) {
                    const json n = json::parse(next, nullptr, false);
                    told = !n.is_discarded() && n.value("method", "") == "notifications/cancelled";
                }
                if (!told) return 4;
                std::cerr << "slow was cancelled" << std::endl;
            } else if (name == "exit") {
                return 0;
            } else {
                reply(text("called " + name));
            }
        } else {
            send({{"jsonrpc", "2.0"},
                  {"id", id},
                  {"error", {{"code", -32601}, {"message", "no method " + method}}}});
        }
    }
    return 0;
}

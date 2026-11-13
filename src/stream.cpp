// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#include "tapto/stream.h"

#include <stdexcept>

using json = nlohmann::json;

namespace tapto {

// --- SseParser ----------------------------------------------------------------

void SseParser::feed(const char* data, std::size_t size, const Handler& on_event) {
    for (std::size_t i = 0; i < size; ++i) {
        const char c = data[i];
        if (!m_started) {
            // A UTF-8 BOM before the first byte is not part of the stream. It
            // can arrive split across pieces, so it is matched a byte at a time.
            static const char kBom[] = "\xEF\xBB\xBF";
            if (m_line.size() < 3 && c == kBom[m_line.size()]) {
                m_line += c;
                if (m_line.size() == 3) {
                    m_line.clear();
                    m_started = true;
                }
                continue;
            }
            m_started = true; // not a BOM: whatever was held is text
        }
        if (c == '\n') {
            if (m_afterCR) {
                m_afterCR = false; // the LF of a CRLF whose CR ended the line
                continue;
            }
            line(m_line, on_event);
            m_line.clear();
        } else if (c == '\r') {
            line(m_line, on_event);
            m_line.clear();
            m_afterCR = true;
            continue;
        } else {
            m_line += c;
        }
        m_afterCR = false;
    }
}

void SseParser::finish(const Handler& on_event) {
    if (!m_line.empty()) {
        line(m_line, on_event);
        m_line.clear();
    }
    dispatch(on_event);
    m_afterCR = false;
}

void SseParser::line(const std::string& text, const Handler& on_event) {
    if (text.empty()) {
        dispatch(on_event);
        return;
    }
    if (text[0] == ':') return; // a comment

    std::string field;
    std::string value;
    const auto colon = text.find(':');
    if (colon == std::string::npos) {
        field = text;
    } else {
        field = text.substr(0, colon);
        value = text.substr(colon + 1);
        if (!value.empty() && value[0] == ' ') value.erase(0, 1);
    }

    if (field == "data") {
        if (m_hasData) m_data += '\n';
        m_data += value;
        m_hasData = true;
    } else if (field == "event") {
        m_event = value;
    }
    // id, retry and unknown fields: nothing a reply needs
}

void SseParser::dispatch(const Handler& on_event) {
    if (m_hasData) {
        SseEvent ev{m_event, m_data};
        m_event.clear();
        m_data.clear();
        m_hasData = false;
        on_event(ev);
    } else {
        m_event.clear(); // an event with no data is not dispatched
    }
}

// --- OpenAIStreamAccumulator --------------------------------------------------

namespace {

std::string str(const json& o, const char* key) {
    if (!o.is_object()) return {};
    auto it = o.find(key);
    if (it == o.end() || !it->is_string()) return {};
    return it->get<std::string>();
}

} // namespace

OpenAIStreamAccumulator::Delta OpenAIStreamAccumulator::add(const json& chunk) {
    Delta out;
    if (!chunk.is_object()) return out;

    // An error after the 200: the server gave up partway through.
    if (chunk.contains("error") && !chunk["error"].is_null()) {
        const json& err = chunk["error"];
        std::string message = err.is_object() ? str(err, "message") : std::string();
        if (message.empty()) message = err.dump();
        throw std::runtime_error("The server reported an error partway through the reply: " + message);
    }

    if (m_id.empty()) m_id = str(chunk, "id");
    if (m_model.empty()) m_model = str(chunk, "model");
    if (chunk.contains("usage") && chunk["usage"].is_object() && !chunk["usage"].empty()) {
        m_usage = chunk["usage"];
    }

    auto choices = chunk.find("choices");
    if (choices == chunk.end() || !choices->is_array()) return out;

    for (const auto& choice : *choices) {
        if (!choice.is_object()) continue;
        // One reply is asked for (n=1); a server that sends more is not followed.
        if (choice.value("index", 0) != 0) continue;
        m_started = true;

        if (choice.contains("finish_reason") && choice["finish_reason"].is_string()) {
            m_finishReason = choice["finish_reason"].get<std::string>();
        }

        auto deltaIt = choice.find("delta");
        if (deltaIt == choice.end() || !deltaIt->is_object()) {
            // A few servers send a whole `message` in the last chunk.
            deltaIt = choice.find("message");
            if (deltaIt == choice.end() || !deltaIt->is_object()) continue;
        }
        const json& delta = *deltaIt;

        for (const char* field : {"reasoning_content", "reasoning"}) {
            const std::string piece = str(delta, field);
            if (!piece.empty()) {
                m_reasoning += piece;
                out.reasoning += piece;
                break; // a server that fills both means the same text
            }
        }
        {
            const std::string piece = str(delta, "content");
            m_content += piece;
            out.text += piece;
        }

        auto calls = delta.find("tool_calls");
        if (calls == delta.end() || !calls->is_array()) continue;
        for (const auto& call : *calls) {
            if (!call.is_object()) continue;
            const std::string id = str(call, "id");

            int index;
            if (call.contains("index") && call["index"].is_number_integer()) {
                index = call["index"].get<int>();
            } else if (m_lastToolIndex >= 0 &&
                       (id.empty() || id == m_toolCalls[m_lastToolIndex].id)) {
                index = m_lastToolIndex; // no index: the call goes on
            } else {
                index = m_toolCalls.empty() ? 0 : m_toolCalls.rbegin()->first + 1;
            }
            m_lastToolIndex = index;
            ToolCall& tc = m_toolCalls[index];

            if (!id.empty()) tc.id = id; // repeated in every piece by some servers
            const std::string type = str(call, "type");
            if (!type.empty()) tc.type = type;

            const json fn = call.value("function", json::object());
            const std::string name = str(fn, "name");
            if (!name.empty() && tc.name.empty()) tc.name = name;

            if (fn.is_object() && fn.contains("arguments")) {
                const json& args = fn["arguments"];
                if (args.is_string()) {
                    tc.arguments += args.get<std::string>();
                } else if (!args.is_null()) {
                    // A server that sends the arguments as an object, whole.
                    tc.arguments = args.dump();
                }
            }
        }
    }
    return out;
}

json OpenAIStreamAccumulator::response(bool interrupted) const {
    json message = {{"role", "assistant"}};

    json toolCalls = json::array();
    if (!interrupted) {
        for (const auto& [index, tc] : m_toolCalls) {
            if (tc.name.empty()) continue; // a fragment with nothing to run
            toolCalls.push_back({
                {"id", tc.id.empty() ? "call_" + std::to_string(index) : tc.id},
                {"type", tc.type.empty() ? std::string("function") : tc.type},
                {"function", {{"name", tc.name},
                              {"arguments", tc.arguments.empty() ? std::string("{}") : tc.arguments}}},
            });
        }
    }

    if (m_content.empty() && !toolCalls.empty()) {
        message["content"] = nullptr; // as the whole reply carries it
    } else {
        message["content"] = m_content;
    }
    if (!m_reasoning.empty()) message["reasoning_content"] = m_reasoning;
    if (!toolCalls.empty()) message["tool_calls"] = toolCalls;

    std::string finish = m_finishReason;
    if (finish.empty()) finish = interrupted ? "interrupted" : (toolCalls.empty() ? "stop" : "tool_calls");

    json resp = {
        {"object", "chat.completion"},
        {"choices", json::array({{{"index", 0}, {"message", message}, {"finish_reason", finish}}})},
    };
    if (!m_id.empty()) resp["id"] = m_id;
    if (!m_model.empty()) resp["model"] = m_model;
    if (!m_usage.is_null()) resp["usage"] = m_usage;
    return resp;
}

} // namespace tapto

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

// An event's data as JSON, or a discarded value when it is not JSON.
json parse_event(const SseEvent& ev) {
    return json::parse(ev.data, nullptr, /*allow_exceptions=*/false);
}

// The message of an `error` object, or the object itself as text.
std::string error_text(const json& err) {
    if (err.is_object()) {
        std::string message = str(err, "message");
        const std::string type = str(err, "type");
        if (!message.empty()) return type.empty() ? message : type + ": " + message;
    }
    return err.is_string() ? err.get<std::string>() : err.dump();
}

[[noreturn]] void throw_stream_error(const json& err) {
    throw std::runtime_error("The server reported an error partway through the reply: " + error_text(err));
}

} // namespace

StreamDelta OpenAIStreamAccumulator::add(const SseEvent& ev) {
    if (ev.data == "[DONE]") {
        m_done = true;
        return {};
    }
    json chunk = parse_event(ev);
    if (chunk.is_discarded()) return {}; // not JSON: nothing a reply is made of
    if (ev.event == "error" && !chunk.contains("error")) throw_stream_error(chunk);
    return addChunk(chunk);
}

StreamDelta OpenAIStreamAccumulator::addChunk(const json& chunk) {
    StreamDelta out;
    if (!chunk.is_object()) return out;

    // An error after the 200: the server gave up partway through.
    if (chunk.contains("error") && !chunk["error"].is_null()) throw_stream_error(chunk["error"]);

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

// --- ClaudeStreamAccumulator --------------------------------------------------

StreamDelta ClaudeStreamAccumulator::add(const SseEvent& ev) {
    StreamDelta out;
    const json data = parse_event(ev);
    if (data.is_discarded() || !data.is_object()) return out;

    // The event's name is in both the `event:` field and the data's `type`;
    // a proxy may drop the first, so the second decides.
    std::string type = str(data, "type");
    if (type.empty()) type = ev.event;

    if (type == "error" || (data.contains("error") && data["error"].is_object())) {
        throw_stream_error(data.value("error", data));
    }
    if (type == "message_start") {
        m_message = data.value("message", json::object());
        m_message.erase("content"); // filled from the blocks
        return out;
    }
    if (type == "message_delta") {
        const json delta = data.value("delta", json::object());
        for (auto it = delta.begin(); it != delta.end(); ++it) m_message[it.key()] = it.value();
        if (data.contains("usage") && data["usage"].is_object()) {
            json& usage = m_message["usage"];
            if (!usage.is_object()) usage = json::object();
            for (auto it = data["usage"].begin(); it != data["usage"].end(); ++it) {
                if (!it.value().is_null()) usage[it.key()] = it.value();
            }
        }
        return out;
    }
    if (type == "message_stop") {
        m_done = true;
        return out;
    }

    const int index = data.value("index", -1);
    if (index < 0) return out; // ping, and anything else not about a block

    if (type == "content_block_start") {
        Block& b = m_blocks[index];
        b.block = data.value("content_block", json::object());
        // Text a block starts with (rare, but allowed) is shown too.
        const std::string kind = str(b.block, "type");
        if (kind == "text") out.text += str(b.block, "text");
        else if (kind == "thinking") out.reasoning += str(b.block, "thinking");
        return out;
    }
    if (type == "content_block_stop") {
        m_blocks[index].stopped = true;
        return out;
    }
    if (type != "content_block_delta") return out;

    Block& b = m_blocks[index];
    const json delta = data.value("delta", json::object());
    const std::string kind = str(delta, "type");
    if (kind == "text_delta") {
        const std::string piece = str(delta, "text");
        b.block["text"] = str(b.block, "text") + piece;
        out.text += piece;
    } else if (kind == "thinking_delta") {
        const std::string piece = str(delta, "thinking");
        b.block["thinking"] = str(b.block, "thinking") + piece;
        out.reasoning += piece;
    } else if (kind == "signature_delta") {
        b.block["signature"] = str(b.block, "signature") + str(delta, "signature");
    } else if (kind == "input_json_delta") {
        b.inputJson += str(delta, "partial_json");
    } else if (kind == "citations_delta") {
        if (!b.block["citations"].is_array()) b.block["citations"] = json::array();
        b.block["citations"].push_back(delta.value("citation", json::object()));
    }
    return out;
}

json ClaudeStreamAccumulator::response(bool interrupted) const {
    json message = m_message;
    if (!message.contains("type")) message["type"] = "message";
    if (!message.contains("role")) message["role"] = "assistant";

    json content = json::array();
    for (const auto& [index, b] : m_blocks) {
        json block = b.block;
        const std::string kind = str(block, "type");
        if (kind == "tool_use" || kind == "server_tool_use") {
            if (interrupted) continue; // will not run
            if (!b.inputJson.empty()) {
                json input = json::parse(b.inputJson, nullptr, /*allow_exceptions=*/false);
                block["input"] = input.is_discarded() ? json::object() : input;
            } else if (!block.contains("input") || !block["input"].is_object()) {
                block["input"] = json::object();
            }
        } else if (kind == "thinking") {
            // A thought is sent back with its signature or not at all.
            if (interrupted && (!b.stopped || str(block, "signature").empty())) continue;
        } else if (kind == "text") {
            if (str(block, "text").empty()) continue; // an empty text block is rejected
        } else if (interrupted && !b.stopped) {
            continue;
        }
        content.push_back(block);
    }
    // An assistant message needs content, and an interrupted one may have none.
    if (content.empty() && interrupted) {
        content.push_back({{"type", "text"}, {"text", "(interrupted)"}});
    }
    message["content"] = content;

    if (!message.contains("stop_reason") || message["stop_reason"].is_null()) {
        message["stop_reason"] = interrupted ? "interrupted" : "end_turn";
    }
    return message;
}

// --- GeminiStreamAccumulator --------------------------------------------------

StreamDelta GeminiStreamAccumulator::add(const SseEvent& ev) {
    StreamDelta out;
    const json data = parse_event(ev);
    if (data.is_discarded()) return out;
    // A stream may be a JSON array of responses when alt=sse was not honoured
    // by a proxy; each element is read the same way.
    if (data.is_array()) {
        for (const auto& element : data) {
            SseEvent one{ev.event, element.dump()};
            const StreamDelta d = add(one);
            out.reasoning += d.reasoning;
            out.text += d.text;
        }
        return out;
    }
    if (!data.is_object()) return out;
    if (data.contains("error")) throw_stream_error(data["error"]);

    if (data.contains("usageMetadata") && data["usageMetadata"].is_object()) m_usage = data["usageMetadata"];
    if (m_modelVersion.empty()) m_modelVersion = str(data, "modelVersion");

    const json candidates = data.value("candidates", json::array());
    if (!candidates.is_array() || candidates.empty() || !candidates[0].is_object()) return out;
    const json& cand = candidates[0];
    for (auto it = cand.begin(); it != cand.end(); ++it) {
        if (it.key() != "content" && !it.value().is_null()) m_candidate[it.key()] = it.value();
    }

    const json parts = cand.value("content", json::object()).value("parts", json::array());
    if (!parts.is_array()) return out;
    for (const auto& part : parts) {
        if (!part.is_object()) continue;
        if (part.contains("text") && part["text"].is_string()) {
            const std::string piece = part["text"].get<std::string>();
            const bool thought = part.value("thought", false);
            if (thought) out.reasoning += piece;
            else out.text += piece;

            // Joined to the text part before it when that is the same kind
            // and carries nothing else; a signature goes with the joined part.
            json* prev = m_parts.empty() ? nullptr : &m_parts.back();
            const bool joins = prev && prev->contains("text") && (*prev)["text"].is_string() &&
                               prev->value("thought", false) == thought &&
                               !prev->contains("thoughtSignature");
            if (joins) {
                (*prev)["text"] = (*prev)["text"].get<std::string>() + piece;
                for (auto f = part.begin(); f != part.end(); ++f) {
                    if (f.key() != "text") (*prev)[f.key()] = f.value();
                }
                continue;
            }
        }
        m_parts.push_back(part);
    }
    return out;
}

json GeminiStreamAccumulator::response(bool interrupted) const {
    json parts = json::array();
    for (const auto& part : m_parts) {
        if (interrupted && part.contains("functionCall")) continue; // will not run
        if (part.contains("text") && part["text"].is_string() && part["text"].get<std::string>().empty() &&
            !part.contains("thoughtSignature")) {
            continue;
        }
        parts.push_back(part);
    }
    // A model turn needs a part, and an interrupted one may have none.
    if (parts.empty() && interrupted) parts.push_back({{"text", "(interrupted)"}});

    json candidate = m_candidate;
    candidate["content"] = {{"role", "model"}, {"parts", parts}};
    if (interrupted && !candidate.contains("finishReason")) candidate["finishReason"] = "INTERRUPTED";

    json resp = {{"candidates", json::array({candidate})}};
    if (!m_usage.is_null()) resp["usageMetadata"] = m_usage;
    if (!m_modelVersion.empty()) resp["modelVersion"] = m_modelVersion;
    return resp;
}

} // namespace tapto

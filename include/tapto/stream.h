// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#pragma once

#include <cstddef>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

// Streamed replies: the server-sent-events framing every provider streams in,
// each dialect's events put back together into the reply its non-streaming
// endpoint would have sent, and the callback a program gets the text through
// as it arrives.

namespace tapto {

// --- What the program is told ------------------------------------------------

// One piece of a streamed reply. Reasoning and Text carry the next piece of
// the chain of thought and of the answer; End says the reply is over (it
// finished, was interrupted, or the connection dropped), so the program can
// close the line it was writing before a status line or the next reply
// takes the screen.
struct StreamEvent {
    enum class Kind { Reasoning, Text, End };
    Kind kind = Kind::Text;
    std::string text;
};

// Called for each piece as it arrives, on the thread running chat()
// (AiConfig::setStreamCallback). The text is what the server sent, unscrubbed:
// a server that leaks channel tokens into the stream leaks them here too.
using StreamCallback = std::function<void(const StreamEvent&)>;

// --- Server-sent events (WHATWG HTML, "Parsing an event stream") -------------

struct SseEvent {
    std::string event; // the `event:` field; empty when the server sent none
    std::string data;  // the `data:` lines joined with '\n'
};

// Turns the bytes of a text/event-stream body, in pieces of any size, into
// events. A line ends in CRLF, LF or CR, and may be split across pieces
// anywhere (a CRLF too, a UTF-8 character too). Comment lines (":" first,
// the keep-alives OpenRouter and others send) and the `id` and `retry`
// fields are dropped. An event is dispatched at its blank line, and only when
// it had data.
class SseParser {
public:
    using Handler = std::function<void(const SseEvent&)>;

    void feed(const char* data, std::size_t size, const Handler& on_event);

    // The body has ended. A last event the server left without its blank line
    // is dispatched rather than lost: the spec drops it, but servers that end
    // the stream that way mean it.
    void finish(const Handler& on_event);

private:
    void line(const std::string& text, const Handler& on_event);
    void dispatch(const Handler& on_event);

    std::string m_line;
    std::string m_event;
    std::string m_data;
    bool m_hasData = false;
    bool m_afterCR = false;   // the last byte was a CR: an LF right after it is the same line end
    bool m_started = false;   // past the optional BOM at the very start
};

// --- A dialect's reply, put back together -------------------------------------

// The chain of thought and the text one event carried, to show.
struct StreamDelta {
    std::string reasoning;
    std::string text;
};

class StreamAccumulator {
public:
    virtual ~StreamAccumulator() = default;

    // Adds one event of the stream. An error the server reports in the stream
    // (after its 200) is thrown as runtime_error.
    virtual StreamDelta add(const SseEvent& ev) = 0;

    // Whether the stream said it is over ([DONE], message_stop); events after
    // that are not passed in.
    virtual bool done() const { return false; }

    // The reply as the dialect's non-streaming endpoint returns it. With
    // `interrupted` (ESC partway through) the tool calls are left out, since
    // none of them will run, and so is anything the next request could not
    // send back as it is (a thought cut short before its signature).
    virtual nlohmann::json response(bool interrupted = false) const = 0;
};

// The openai dialect: `chat.completion.chunk` objects back into a
// `chat.completion`. What it copes with:
//   - chain of thought in `reasoning_content` or `reasoning`, as with whole replies
//   - tool calls in pieces: the id and name in the first, then the arguments
//     a piece at a time, matched up by `index`; a server that sends no index
//     continues the last call unless the piece brings a new id
//   - a server that repeats the id or the name in every piece, or sends a call whole
//   - `usage` in a last chunk with no choices (stream_options.include_usage),
//     or on every chunk; the last one sent wins
//   - an `error` object in the stream after the 200
class OpenAIStreamAccumulator : public StreamAccumulator {
public:
    StreamDelta add(const SseEvent& ev) override;
    bool done() const override { return m_done; }
    nlohmann::json response(bool interrupted = false) const override;

    // One parsed chunk; add() calls it for each event that is not [DONE].
    StreamDelta addChunk(const nlohmann::json& chunk);

    // Whether any choice delta has arrived.
    bool started() const { return m_started; }

private:
    struct ToolCall {
        std::string id;
        std::string type;
        std::string name;
        std::string arguments;
    };

    bool m_done = false;
    bool m_started = false;
    std::string m_content;
    std::string m_reasoning;
    std::map<int, ToolCall> m_toolCalls;
    int m_lastToolIndex = -1;
    std::string m_finishReason;
    nlohmann::json m_usage;
    std::string m_id;
    std::string m_model;
};

// The claude dialect: the Messages API's events (message_start,
// content_block_start / _delta / _stop, message_delta, message_stop, ping,
// error) back into a `message`. Text, thinking with its signature, a
// redacted thought and a tool_use whose input arrives as pieces of JSON are
// put together; a block of a type it does not know is kept as it started.
// The usage is message_start's, with what message_delta reports on top.
class ClaudeStreamAccumulator : public StreamAccumulator {
public:
    StreamDelta add(const SseEvent& ev) override;
    bool done() const override { return m_done; }
    nlohmann::json response(bool interrupted = false) const override;

private:
    struct Block {
        nlohmann::json block;   // as content_block_start gave it, filled in by the deltas
        std::string inputJson;  // a tool_use's input, in pieces
        bool stopped = false;
    };

    bool m_done = false;
    nlohmann::json m_message = nlohmann::json::object();
    std::map<int, Block> m_blocks;
};

// The gemini dialect: each event of streamGenerateContent?alt=sse is a whole
// GenerateContentResponse holding the next parts. Text parts that follow one
// another are joined (a thought with a thought, an answer with an answer),
// a thoughtSignature stays on the part it came with, and function calls,
// which arrive whole, are kept as they are. The last usageMetadata and
// finishReason win.
class GeminiStreamAccumulator : public StreamAccumulator {
public:
    StreamDelta add(const SseEvent& ev) override;
    nlohmann::json response(bool interrupted = false) const override;

private:
    nlohmann::json m_parts = nlohmann::json::array();
    nlohmann::json m_candidate = nlohmann::json::object(); // finishReason, finishMessage, ...
    nlohmann::json m_usage;
    std::string m_modelVersion;
};

} // namespace tapto

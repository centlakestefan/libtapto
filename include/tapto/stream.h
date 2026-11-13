// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#pragma once

#include <cstddef>
#include <functional>
#include <map>
#include <string>

#include <nlohmann/json.hpp>

// Streamed replies: the server-sent-events framing every provider streams in,
// the openai dialect's chunks put back together into the reply the
// non-streaming endpoint would have sent, and the callback a program gets the
// text through as it arrives.

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

// --- The openai dialect -------------------------------------------------------

// Puts the `chat.completion.chunk` objects of one streamed reply back into
// the `chat.completion` the non-streaming endpoint returns, so everything
// after the request is the same either way. What it copes with:
//   - chain of thought in `reasoning_content` or `reasoning`, as with whole replies
//   - tool calls in pieces: the id and name in the first, then the arguments
//     a piece at a time, matched up by `index`; a server that sends no index
//     continues the last call unless the piece brings a new id
//   - a server that repeats the id or the name in every piece, or sends a call whole
//   - `usage` in a last chunk with no choices (stream_options.include_usage),
//     or on every chunk; the last one sent wins
//   - an `error` object in the stream after the 200: thrown as runtime_error
class OpenAIStreamAccumulator {
public:
    struct Delta {
        std::string reasoning;
        std::string text;
    };

    // Adds one chunk (the parsed data of one event). Returns the reasoning and
    // text it carried, to show.
    Delta add(const nlohmann::json& chunk);

    // Whether any choice delta has arrived.
    bool started() const { return m_started; }

    // The reply as a non-streaming `chat.completion`: choices[0].message,
    // choices[0].finish_reason and usage. With `interrupted`, tool calls are
    // left out (their arguments may be cut short and none of them will run),
    // and the finish reason is "interrupted" unless the server had sent one.
    nlohmann::json response(bool interrupted = false) const;

private:
    struct ToolCall {
        std::string id;
        std::string type;
        std::string name;
        std::string arguments;
    };

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

} // namespace tapto

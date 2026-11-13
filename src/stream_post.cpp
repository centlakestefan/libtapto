// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#include "stream_post.h"

#include <cstdint>
#include <memory>
#include <stdexcept>

#include "tapto/log.h"

namespace tapto {

httplib::Result post_stream(httplib::Client& client, const std::string& path,
                            const httplib::Headers& headers, const std::string& body,
                            const AiConfig& config, const CancellationToken* cancel,
                            StreamAccumulator& acc, StreamOutcome& out) {
    out = StreamOutcome{};

    httplib::Request req;
    req.method = "POST";
    req.path = path;
    req.headers = headers;
    req.headers.emplace("Accept", "text/event-stream");
    req.body = body;

    const StreamCallback& show = config.streamCallback();
    SseParser parser;
    bool isStream = false;
    std::size_t events = 0;
    std::string streamError;
    std::string otherBody; // an error's body, or a whole reply

    auto onEvent = [&](const SseEvent& ev) {
        if (acc.done() || !streamError.empty()) return;
        ++events;
        try {
            const StreamDelta delta = acc.add(ev);
            if (show) {
                if (!delta.reasoning.empty()) {
                    show({StreamEvent::Kind::Reasoning, delta.reasoning});
                    out.shown = true;
                }
                if (!delta.text.empty()) {
                    show({StreamEvent::Kind::Text, delta.text});
                    out.shown = true;
                }
            }
        } catch (const std::exception& e) {
            streamError = e.what(); // dealt with once the request has returned
        }
    };

    req.response_handler = [&](const httplib::Response& r) {
        isStream = r.status == 200 &&
                   r.get_header_value("Content-Type").find("text/event-stream") != std::string::npos;
        return true;
    };
    req.content_receiver = [&](const char* data, std::size_t size, std::uint64_t, std::uint64_t) {
        if (!isStream) {
            otherBody.append(data, size);
            return true;
        }
        parser.feed(data, size, onEvent);
        if (!streamError.empty()) return false;
        // While the server is silent (a long prompt being read) nothing
        // arrives, and the poll waits with it.
        if (cancel && cancel->check()) {
            out.cancelled = true;
            return false;
        }
        return true;
    };

    auto res = std::make_unique<httplib::Response>();
    httplib::Error error = httplib::Error::Success;
    const bool ok = client.send(req, *res, error);

    if (isStream) {
        if (ok) parser.finish(onEvent);
        if (out.shown) show({StreamEvent::Kind::End, std::string()});
        mclog("Stream: " + std::to_string(events) + " event(s)" + (acc.done() ? "" : ", no end marker") +
              (out.cancelled ? ", stopped by the user" : "") +
              (streamError.empty() ? "" : ", error: " + streamError) + "\n");

        if (!streamError.empty()) {
            if (out.shown) throw std::runtime_error(streamError);
            auto retry = std::make_unique<httplib::Response>();
            retry->status = 503;
            retry->body = streamError;
            return httplib::Result(std::move(retry), httplib::Error::Success);
        }
        if (ok || out.cancelled) {
            out.handled = true;
            out.response = acc.response(/*interrupted=*/out.cancelled);
        }
    }
    if (!ok) return httplib::Result(nullptr, error);
    res->body = std::move(otherBody);
    return httplib::Result(std::move(res), httplib::Error::Success);
}

void show_whole(const StreamCallback& show, const std::string& reasoning, const std::string& text) {
    if (!show || (reasoning.empty() && text.empty())) return;
    if (!reasoning.empty()) show({StreamEvent::Kind::Reasoning, reasoning});
    if (!text.empty()) show({StreamEvent::Kind::Text, text});
    show({StreamEvent::Kind::End, std::string()});
}

} // namespace tapto

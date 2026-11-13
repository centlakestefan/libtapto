// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#pragma once

// The streamed request, the same for every dialect: private to the provider
// clients, which differ only in the path, the body and how a reply is put
// back together (tapto/stream.h).

#include <string>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include "tapto/aiconfig.h"
#include "tapto/cancel.h"
#include "tapto/stream.h"

namespace tapto {

// What a streamed request came to, beside its HTTP result.
struct StreamOutcome {
    bool handled = false;   // the body was an event stream; `response` is the reply
    bool cancelled = false; // ESC stopped it; `response` is what had arrived
    bool shown = false;     // some of it reached the stream callback
    nlohmann::json response;
};

// POSTs `body` asking for an event stream, and gives each event to `acc` as it
// arrives, telling the config's stream callback what it carried. ESC is
// polled as each piece arrives and stops the request, which closes the
// connection and with it the server's work.
//
// The result is what the caller's retry handling already reads:
//   - a connection that failed: the error, as from Post
//   - a status other than 200, or a 200 that is a whole reply instead of a
//     stream (a server that ignores the ask): that response, body and all
//   - a streamed 200: a response with an empty body, and `out.handled`
//   - an error the server reported in the stream before anything was shown:
//     a 503 with the error as its body, so it is retried like one
// An error in the stream after something was shown is thrown: asking again
// would show the reply a second time, and a different one.
httplib::Result post_stream(httplib::Client& client, const std::string& path,
                            const httplib::Headers& headers, const std::string& body,
                            const AiConfig& config, const CancellationToken* cancel,
                            StreamAccumulator& acc, StreamOutcome& out);

// Tells the stream callback a whole reply at once, for a server that was asked
// for a stream and answered with the complete reply instead, so a program
// showing replies as they stream still shows this one. Nothing when both are empty.
void show_whole(const StreamCallback& show, const std::string& reasoning, const std::string& text);

} // namespace tapto

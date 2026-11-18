// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#pragma once

#include <string>
#include <utility>

#include "tapto/compact.h"
#include "tapto/stream.h"
#include "tapto/usage.h"

// Lightweight settings object for the AI backends.
class AiConfig {
public:
    int maxOutputTokens() const { return m_maxOutputTokens; }
    int maxToolIterations() const { return m_maxToolIterations; }
    int connectionTimeoutSeconds() const { return m_connectionTimeoutSeconds; }
    int readTimeoutSeconds() const { return m_readTimeoutSeconds; }
    // Older names; the timeouts apply to every dialect, not just openai.
    int openaiConnectionTimeoutSeconds() const { return m_connectionTimeoutSeconds; }
    int openaiReadTimeoutSeconds() const { return m_readTimeoutSeconds; }
    const std::string& effort() const { return m_effort; }
    const std::string& openaiReasoningEffort() const { return m_reasoningEffort; }
    int keepRecentImages() const { return m_keepRecentImages; }
    bool printCot() const { return m_printCot; }
    const std::string& userAgent() const { return m_userAgent; }
    const tapto::UsageCallback& usageCallback() const { return m_usageCallback; }
    const tapto::RetryCallback& retryCallback() const { return m_retryCallback; }
    bool stream() const { return m_stream; }
    const tapto::StreamCallback& streamCallback() const { return m_streamCallback; }
    bool retryLostReply() const { return m_retryLostReply; }
    int retryForSeconds() const { return m_retryForSeconds; }
    bool compactInTurn() const { return m_compactInTurn; }
    int contextWindow() const { return m_contextWindow; }
    const tapto::CompactCallback& compactCallback() const { return m_compactCallback; }
    // Whether the pieces of a reply reach the program as they arrive, so the
    // clients do not show them again through ui::emit_intermediate.
    bool showsStream() const { return m_stream && static_cast<bool>(m_streamCallback); }

    void setMaxOutputTokens(int v) { m_maxOutputTokens = v; }
    void setMaxToolIterations(int v) { m_maxToolIterations = v; }
    void setConnectionTimeoutSeconds(int v) { m_connectionTimeoutSeconds = v; }
    void setReadTimeoutSeconds(int v) { m_readTimeoutSeconds = v; }
    void setOpenaiConnectionTimeoutSeconds(int v) { m_connectionTimeoutSeconds = v; }
    void setOpenaiReadTimeoutSeconds(int v) { m_readTimeoutSeconds = v; }
    void setEffort(std::string v) { m_effort = std::move(v); }
    void setOpenaiReasoningEffort(std::string v) { m_reasoningEffort = std::move(v); }
    void setKeepRecentImages(int v) { m_keepRecentImages = v; }
    void setPrintCot(bool v) { m_printCot = v; }
    void setUserAgent(std::string v) { m_userAgent = std::move(v); }
    void setUsageCallback(tapto::UsageCallback v) { m_usageCallback = std::move(v); }
    void setRetryCallback(tapto::RetryCallback v) { m_retryCallback = std::move(v); }
    void setStream(bool v) { m_stream = v; }
    void setStreamCallback(tapto::StreamCallback v) { m_streamCallback = std::move(v); }
    void setRetryLostReply(bool v) { m_retryLostReply = v; }
    void setRetryForSeconds(int v) { m_retryForSeconds = v; }
    void setCompactInTurn(bool v) { m_compactInTurn = v; }
    void setContextWindow(int v) { m_contextWindow = v; }
    void setCompactCallback(tapto::CompactCallback v) { m_compactCallback = std::move(v); }

private:
    int m_maxOutputTokens = 16000;
    int m_maxToolIterations = 200;
    int m_connectionTimeoutSeconds = 30;

    // How long to wait for the provider's answer. Without m_stream the
    // response arrives all at once, so this is the whole generation: a 16k-token answer from a local model
    // decoding at 14 tok/s takes nineteen minutes and arrives all at once at
    // the end. A timeout shorter than the generation does not just fail the
    // turn -- the retry re-sends the same request, the server cancels the
    // work in progress, and the cycle repeats until the retry budget is spent,
    // which is the worst of every world. Streamed, it is the longest silence
    // between two pieces instead, which in practice is the time to the first
    // token. Programs set this from config (read-timeout); the default is for
    // a hosted provider.
    int m_readTimeoutSeconds = 300;

    // Claude's thinking depth and overall token spend, sent as
    // output_config.effort. Empty leaves the server default. A program whose
    // task is long-horizon and agentic (driving a GUI) wants "high"; a chat
    // client can leave it alone. The program decides, not the library.
    std::string m_effort;

    // The openai dialect's equivalent, sent as `reasoning_effort`. Empty means
    // the key is absent from the request, which is not the same as sending a
    // default: the server picks its own, and servers that have never heard of
    // the field keep working. No default is assumed here because, unlike
    // Claude's effort, the accepted values differ from one endpoint to the next.
    std::string m_reasoningEffort;

    // How many of the newest tool-produced images stay in the conversation as
    // real images; older ones are replaced with a placeholder before each
    // request. Full-screen PNGs are hundreds of kilobytes once base64-encoded
    // and the whole history is re-sent every request, so without a cap a long
    // run ends in HTTP 413. Three keeps "before, after, now" legible while
    // bounding the request size. 0 disables pruning. Only matters to programs
    // whose tools produce images (see tool_image.h).
    int m_keepRecentImages = 3;

    bool m_printCot = true; // surface intermediate reasoning/text to the user

    // Sent as the User-Agent header of every request, e.g.
    // "tapto-code/1.0.5 (d8c8383; windows)", so a proxy in front of the
    // provider (LiteLLM, a corporate gateway) can see which program and
    // version is calling, and turn away one that is too old. Empty sends
    // no header of ours and leaves the HTTP library's default. The program
    // names itself, not the library.
    std::string m_userAgent;

    // Told the tokens of each request that succeeded (tapto/usage.h), for a
    // program that accounts for them: a server charging them to a tenant.
    // Empty: nobody is told.
    tapto::UsageCallback m_usageCallback;
    tapto::RetryCallback m_retryCallback;

    // Ask for the reply as a stream (tapto/stream.h). The reply comes back the
    // same, but the read timeout becomes the longest silence instead of the
    // whole generation, and ESC stops a reply partway through. Every dialect
    // streams: openai's chunks, claude's Messages events and gemini's
    // streamGenerateContent. Off by default: a program opts in.
    bool m_stream = false;

    // Told each piece of a streamed reply as it arrives. When set, the pieces
    // are the program's to show, so the library does not show them again
    // through ui::emit_intermediate; the text chat() returns is still the
    // whole reply, which the program has then already shown. Empty: nothing
    // is shown until the reply is complete, as without streaming.
    tapto::StreamCallback m_streamCallback;

    // A streamed reply lost partway through (the connection dropped, the
    // server restarted, an error in the stream after part of it was shown):
    // asked again like any failed request, the stream callback having been
    // told its End. Off: thrown, since a person watching would see the
    // reply a second time, and a different one. A program whose replies
    // nobody watches as they come (a server's agents) turns it on.
    bool m_retryLostReply = false;

    // How long a request keeps being sent again after its connection failed,
    // the server answered with an error (5xx) or said slow down (429),
    // counted from the first failure (tapto/retry.h). 0: a count instead,
    // 5 retries (10 for 429) whose doubling waits add up to about a minute,
    // which a server restarting or a network switch's upgrade outlasts. A
    // program whose requests nobody waits on (a server's agents) sets it
    // long. The waits stop at a cancel either way.
    int m_retryForSeconds = 0;

    // Compaction inside a turn (tapto/compact.h): chat() summarizes the
    // conversation and goes on from the summary when the next request would
    // pass the context window, or when the provider refused one as over its
    // context length. Off: such a request fails, as before, and a person
    // types /compact. A program whose agents run on their own turns it on.
    bool m_compactInTurn = false;
    // The model's context window in tokens, input and reply together. 0:
    // unknown, and only the provider's refusal starts a compaction. Known,
    // a request is also kept within it: compacted before it would not fit,
    // its reply limit cut to what is left when that still falls short.
    int m_contextWindow = 0;
    tapto::CompactCallback m_compactCallback;
};

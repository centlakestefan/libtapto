// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#pragma once

#include <cstdint>
#include <functional>
#include <string>

#include <nlohmann/json.hpp>

namespace tapto {

// What one provider request cost, in tokens, the same way for every dialect:
//   input        input tokens neither read from nor written to a cache
//   cache_read   input tokens read from the provider's prompt cache
//   cache_write  input tokens written to it (Claude reports them; the others
//                cache without charging for it, and report 0)
//   output       the answer, its reasoning included
// So input + cache_read + cache_write is the whole prompt.
struct TokenUsage {
    std::string model;
    std::uint64_t input = 0;
    std::uint64_t output = 0;
    std::uint64_t cache_read = 0;
    std::uint64_t cache_write = 0;
};

// Called once for each request that succeeded and reported its usage, on the
// thread that made it (AiConfig::setUsageCallback).
using UsageCallback = std::function<void(const TokenUsage&)>;

namespace usage_detail {
inline std::uint64_t num(const nlohmann::json& o, const char* key) {
    if (!o.is_object()) return 0;
    auto it = o.find(key);
    if (it == o.end() || !it->is_number()) return 0;
    const double v = it->get<double>();
    return v > 0 ? static_cast<std::uint64_t>(v) : 0;
}
inline std::uint64_t less(std::uint64_t a, std::uint64_t b) { return a > b ? a - b : 0; }
} // namespace usage_detail

// The usage in a response of the dialect ("claude", "openai", "gemini"):
// false when the response reports none.
inline bool usage_from(const std::string& dialect, const nlohmann::json& resp, TokenUsage& out) {
    using namespace usage_detail;
    if (!resp.is_object()) return false;
    if (dialect == "claude") {
        auto it = resp.find("usage");
        if (it == resp.end() || !it->is_object()) return false;
        out.input = num(*it, "input_tokens");
        out.output = num(*it, "output_tokens");
        out.cache_read = num(*it, "cache_read_input_tokens");
        out.cache_write = num(*it, "cache_creation_input_tokens");
        return true;
    }
    if (dialect == "openai") {
        // chat/completions: prompt_tokens, completion_tokens and
        // prompt_tokens_details.cached_tokens; the responses API: input_tokens,
        // output_tokens and input_tokens_details.cached_tokens. Either way the
        // cached tokens are part of the prompt's count.
        auto it = resp.find("usage");
        if (it == resp.end() || !it->is_object() || it->empty()) return false;
        const nlohmann::json& u = *it;
        const bool responses = u.contains("input_tokens");
        const std::uint64_t prompt = num(u, responses ? "input_tokens" : "prompt_tokens");
        const char* details = responses ? "input_tokens_details" : "prompt_tokens_details";
        const std::uint64_t cached = u.contains(details) ? num(u[details], "cached_tokens") : 0;
        out.input = less(prompt, cached);
        out.cache_read = cached;
        out.cache_write = 0;
        out.output = num(u, responses ? "output_tokens" : "completion_tokens");
        return true;
    }
    if (dialect == "gemini") {
        // promptTokenCount includes cachedContentTokenCount; the thoughts are
        // counted apart from the candidates.
        auto it = resp.find("usageMetadata");
        if (it == resp.end() || !it->is_object()) return false;
        const std::uint64_t cached = num(*it, "cachedContentTokenCount");
        out.input = less(num(*it, "promptTokenCount"), cached);
        out.cache_read = cached;
        out.cache_write = 0;
        out.output = num(*it, "candidatesTokenCount") + num(*it, "thoughtsTokenCount");
        return true;
    }
    return false;
}

// For the clients: hands the response's usage to the callback, if there is
// one. A callback that throws does not fail the request.
inline void report_usage(const UsageCallback& cb, const std::string& dialect, const std::string& model,
                         const nlohmann::json& resp) {
    if (!cb) return;
    TokenUsage u;
    if (!usage_from(dialect, resp, u)) return;
    u.model = model;
    try {
        cb(u);
    } catch (...) {
    }
}

} // namespace tapto

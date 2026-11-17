// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#include "tapto/compact.h"

#include <algorithm>
#include <cctype>
#include <exception>

#include "tapto/aibackend.h"
#include "tapto/aiconfig.h"
#include "tapto/log.h"

using json = nlohmann::json;

namespace tapto {

// The smallest reply limit a request is cut to; below it, it is sent as
// configured and the provider says whether it fits.
constexpr int kMinReplyTokens = 1024;

const char* const kCompactPrompt =
    "This conversation has grown too long for the model's context window and is being compacted. "
    "Summarize the entire conversation so far as a compact, structured note for carrying on with the "
    "task: the task's goal, the decisions made and why, the files read or changed and what changed in "
    "them, what is done, what remains and what to do next, and what was learned that the rest of the "
    "work needs (commands, errors and how they were solved, findings). Tool outputs shown as omitted "
    "were long; say what they were for. Reply with the summary only.";

namespace {

const char* const kSeedMark = "\n\n---\n(This conversation outgrew the model's context window";

// An image counts as this many characters (about 1600 tokens), not its
// base64 payload's hundreds of kilobytes.
constexpr std::size_t kImageChars = 6400;

std::size_t chars_of(const json& j) {
    if (j.is_string()) {
        const std::string& s = j.get_ref<const std::string&>();
        return s.rfind("data:image/", 0) == 0 ? kImageChars : s.size();
    }
    std::size_t n = 0;
    if (j.is_object()) {
        // Claude's {"type":"base64","data":...}, Gemini's inlineData
        if (j.contains("data") && (j.value("type", std::string()) == "base64" || j.contains("mimeType")))
            return kImageChars;
        for (const auto& [k, v] : j.items()) n += k.size() + chars_of(v);
    } else if (j.is_array()) {
        for (const auto& v : j) n += chars_of(v);
    } else {
        n += 4;
    }
    return n;
}

} // namespace

bool is_context_overflow(const std::string& error) {
    std::string e = error;
    std::transform(e.begin(), e.end(), e.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    for (const char* m : {"maximum context length", "context_length_exceeded", "context length", "context window",
                          "prompt is too long", "input token count", "too many input tokens",
                          "maximum number of tokens", "exceeds the context"})
        if (e.find(m) != std::string::npos) return true;
    return false;
}

std::string first_user_text(const json& history) {
    if (!history.is_array()) return {};
    for (const json& m : history) {
        if (!m.is_object() || m.value("role", std::string()) != "user") continue;
        if (m.contains("content") && m["content"].is_string()) return m["content"].get<std::string>();
        std::string text;
        const json* blocks = m.contains("content") && m["content"].is_array() ? &m["content"]
                             : m.contains("parts") && m["parts"].is_array()   ? &m["parts"]
                                                                              : nullptr;
        if (!blocks) continue;
        for (const json& b : *blocks)
            if (b.is_object() && b.contains("text") && b["text"].is_string() &&
                b.value("type", std::string("text")) == "text")
                text += (text.empty() ? "" : "\n") + b["text"].get<std::string>();
        if (!text.empty()) return text;
    }
    return {};
}

std::string task_of_seed(const std::string& first_message) {
    const auto at = first_message.find(kSeedMark);
    return at == std::string::npos ? first_message : first_message.substr(0, at);
}

std::string compact_seed(const std::string& task, const std::string& summary, const std::string& state) {
    std::string s = task + kSeedMark +
                    " and was compacted. What was done so far is summarized below: carry on with the task from "
                    "where it stands. What tools showed before is not in this conversation any more; read again "
                    "what you need.)\n\n## Summary of the work so far\n\n" +
                    summary;
    if (!state.empty()) s += "\n\n## The state of the work now\n\n" + state;
    return s;
}

std::size_t history_chars(const json& history) { return chars_of(history); }

} // namespace tapto

int AiBackend::outputLimit(const AiConfig& cfg) const {
    return m_requestOutputLimit > 0 ? m_requestOutputLimit : cfg.maxOutputTokens();
}

void AiBackend::fitWindow(const AiConfig& cfg) {
    m_requestOutputLimit = 0;
    if (!cfg.compactInTurn() || m_compacting) return;
    const std::size_t window = cfg.contextWindow() > 0 ? static_cast<std::size_t>(cfg.contextWindow()) : 0;
    // what the next request holds: the last one's input as the provider
    // counted it and, at about four characters a token, what came since; with
    // no count, the whole of it so
    auto estimate = [&](std::size_t chars) {
        if (m_lastInputTokens > 0 && m_sentChars > 0 && chars >= m_sentChars)
            return m_lastInputTokens + (chars - m_sentChars) / 4;
        return (chars + getSystemPrompt().size()) / 4;
    };
    std::size_t chars = tapto::history_chars(getHistory());
    if (window) {
        const std::size_t reply = static_cast<std::size_t>(std::max(cfg.maxOutputTokens(), 0));
        std::size_t input = estimate(chars);
        if (input + reply > window &&
            compactTurn(cfg, "the next request (about " + std::to_string(input) + " tokens and a reply of " +
                                 std::to_string(reply) + ") would not fit the context window of " +
                                 std::to_string(window))) {
            chars = tapto::history_chars(getHistory());
            input = estimate(chars);
        }
        if (input + reply > window && input + tapto::kMinReplyTokens <= window) {
            m_requestOutputLimit = static_cast<int>(window - input);
            mclog("[compact] reply limit cut to " + std::to_string(m_requestOutputLimit) +
                  " tokens to fit the context window\n");
        }
    }
    m_sentChars = chars;
}

bool AiBackend::compactTurn(const AiConfig& cfg, const std::string& why) {
    if (!cfg.compactInTurn() || m_compacting) return false;
    const json before = getHistory();
    if (!before.is_array() || before.empty()) return false;
    const std::string task = tapto::task_of_seed(tapto::first_user_text(before));
    const std::size_t tokens_before = m_lastInputTokens;
    const std::size_t sent_before = m_sentChars;
    m_compacting = true;
    std::string summary;
    try {
        const json trimmed = buildTrimmedHistoryForSummary();
        // its reply within what the window leaves, when it is known
        int reply = tapto::kCompactReplyTokens;
        if (cfg.contextWindow() > 0) {
            const long long left = static_cast<long long>(cfg.contextWindow()) -
                                   static_cast<long long>((tapto::history_chars(trimmed) + getSystemPrompt().size() +
                                                           std::string(tapto::kCompactPrompt).size()) / 4);
            reply = static_cast<int>(std::max<long long>(tapto::kMinReplyTokens, std::min<long long>(reply, left)));
        }
        summary = requestOnce(trimmed, tapto::kCompactPrompt, reply);
    } catch (const std::exception& e) {
        mclog(std::string("[compact] the summary failed: ") + e.what() + "\n");
        summary.clear();
    }
    m_compacting = false;
    if (summary.find_first_not_of(" \t\r\n") == std::string::npos) {
        // the conversation as it was, its accounting too (the summary's
        // request had its own)
        m_lastInputTokens = tokens_before;
        m_sentChars = sent_before;
        mclog("[compact] no summary; the conversation is kept as it was (" + why + ")\n");
        return false;
    }
    tapto::CompactInfo info;
    info.why = why;
    info.tokens_before = tokens_before ? tokens_before : tapto::history_chars(before) / 4;
    info.summary_chars = summary.size();
    std::string state;
    if (cfg.compactCallback()) {
        try {
            state = cfg.compactCallback()(info);
        } catch (const std::exception& e) {
            mclog(std::string("[compact] the program's state of the work failed: ") + e.what() + "\n");
        }
    }
    beginWith(tapto::compact_seed(task, summary, state));
    mclog("[compact] " + why + ": the conversation (about " + std::to_string(info.tokens_before) +
          " tokens) starts again from a " + std::to_string(summary.size()) + "-character summary\n");
    return true;
}

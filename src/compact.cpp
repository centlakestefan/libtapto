// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#include "tapto/compact.h"

#include <algorithm>
#include <cctype>
#include <exception>
#include <stdexcept>

#include "tapto/aibackend.h"
#include "tapto/aiconfig.h"
#include "tapto/cancel.h"
#include "tapto/log.h"

using json = nlohmann::json;

namespace tapto {

// The smallest reply limit a request is cut to; below it, it is sent as
// configured and the provider says whether it fits.
constexpr int kMinReplyTokens = 1024;

const char* const kCompactPrompt =
    "The conversation above has grown too long for the model's context window and is being compacted. "
    "Summarize it as a compact, structured note for carrying on with the task: the task's goal, the "
    "decisions made and why, the files read or changed and what changed in them, what is done, what "
    "remains and what to do next, and what was learned that the rest of the work needs (commands, errors "
    "and how they were solved, findings). Tool outputs shown as omitted were long; say what they were "
    "for. Reply with the summary only.";

namespace {

const char* const kSeedMark = "\n\n---\n(This conversation outgrew the model's context window";

// An image counts as this many characters (about 1600 tokens), not its
// base64 payload's hundreds of kilobytes.
constexpr std::size_t kImageChars = 6400;

// A tool call's arguments in a transcript: the start of them.
constexpr std::size_t kTranscriptArgs = 2000;

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

std::string clip(const std::string& s, std::size_t n) {
    if (s.size() <= n) return s;
    std::size_t at = n;
    while (at > 0 && (static_cast<unsigned char>(s[at]) & 0xC0) == 0x80) --at;
    return s.substr(0, at) + "... (" + std::to_string(s.size()) + " characters in all)";
}

std::string text_of(const json& content) {
    if (content.is_string()) return content.get<std::string>();
    if (!content.is_array()) return content.is_null() ? std::string() : content.dump();
    std::string out;
    for (const json& b : content) {
        if (b.is_string()) out += b.get<std::string>();
        else if (b.is_object() && b.contains("text") && b["text"].is_string()) out += b["text"].get<std::string>();
        else if (b.is_object() && (b.contains("image_url") || b.value("type", std::string()) == "image"))
            out += "[an image]";
        if (!out.empty() && out.back() != '\n') out += "\n";
    }
    return out;
}

std::string args_text(const json& a) {
    return clip(a.is_string() ? a.get<std::string>() : a.dump(), kTranscriptArgs);
}

} // namespace

bool is_context_overflow(const std::string& error) {
    std::string e = error;
    std::transform(e.begin(), e.end(), e.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    // a refusal of the request: Bad Request (400), Client error (413),
    // Unexpected HTTP status 400 (gemini)
    bool refused = false;
    for (const char* s : {"(400)", "(413)", "status 400", "status 413"})
        refused = refused || e.find(s) != std::string::npos;
    if (!refused) return false;
    for (const char* m : {"maximum context length", "context_length_exceeded", "context length", "context window",
                          "prompt is too long", "input token count", "too many input tokens",
                          "maximum number of tokens", "exceeds the context", "context size",
                          "exceed_context_size"})
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

std::string transcript(const json& history) {
    std::string out;
    if (!history.is_array()) return out;
    auto said = [&](const std::string& who, const std::string& what) {
        if (what.find_first_not_of(" \t\r\n") == std::string::npos) return;
        out += "### " + who + "\n" + what + (what.back() == '\n' ? "" : "\n") + "\n";
    };
    for (const json& m : history) {
        if (!m.is_object()) continue;
        const std::string role = m.value("role", std::string());
        // OpenAI: a tool's result is a message of its own
        if (role == "tool") {
            said("tool result", text_of(m.value("content", json())));
            continue;
        }
        const std::string who = role == "model" ? "assistant" : role;
        if (m.contains("tool_calls") && m["tool_calls"].is_array()) { // OpenAI's calls
            std::string calls = text_of(m.value("content", json()));
            for (const json& c : m["tool_calls"])
                if (c.contains("function"))
                    calls += "[calls " + c["function"].value("name", std::string()) + " with " +
                             args_text(c["function"].value("arguments", json::object())) + "]\n";
            said(who, calls);
            continue;
        }
        const json* blocks = m.contains("content") && m["content"].is_array() ? &m["content"]
                             : m.contains("parts") && m["parts"].is_array()   ? &m["parts"]
                                                                              : nullptr;
        if (!blocks) {
            said(who, text_of(m.value("content", json())));
            continue;
        }
        std::string text, results;
        for (const json& b : *blocks) {
            if (!b.is_object()) continue;
            const std::string type = b.value("type", std::string());
            if (type == "thinking" || b.value("thought", false)) continue; // its reasoning: not the work
            if (type == "tool_use")
                text += "[calls " + b.value("name", std::string()) + " with " + args_text(b.value("input", json())) +
                        "]\n";
            else if (type == "tool_result")
                results += text_of(b.value("content", json())) + "\n";
            else if (b.contains("functionCall"))
                text += "[calls " + b["functionCall"].value("name", std::string()) + " with " +
                        args_text(b["functionCall"].value("args", json::object())) + "]\n";
            else if (b.contains("functionResponse")) {
                const json r = b["functionResponse"].value("response", json::object());
                results += text_of(r.contains("content") ? r["content"] : r) + "\n";
            } else if (b.contains("text") && b["text"].is_string())
                text += b["text"].get<std::string>() + "\n";
            else if (b.contains("inlineData") || type == "image")
                text += "[an image]\n";
        }
        said(who, text);
        said("tool result", results);
    }
    return out;
}

std::string task_of_seed(const std::string& first_message) {
    const auto at = first_message.find(kSeedMark);
    return at == std::string::npos ? first_message : first_message.substr(0, at);
}

std::string compact_seed(const std::string& task, const std::string& turn, const std::string& summary,
                         const std::string& state) {
    std::string s = task + kSeedMark +
                    " and was compacted. What was done so far is summarized below: carry on with the task from "
                    "where it stands. What tools showed before is not in this conversation any more; read again "
                    "what you need.)\n\n";
    if (!turn.empty() && turn != task) s += "## The request being worked on now\n\n" + turn + "\n\n";
    s += "## Summary of the work so far\n\n" + summary;
    if (!state.empty()) s += "\n\n## The state of the work now\n\n" + state;
    return s;
}

std::size_t history_chars(const json& history) { return chars_of(history); }

} // namespace tapto

int AiBackend::outputLimit(const AiConfig& cfg) const {
    return m_requestOutputLimit > 0 ? m_requestOutputLimit : cfg.maxOutputTokens();
}

const AiConfig& AiBackend::streamConfig(const AiConfig& cfg) const { return m_quiet ? *m_quiet : cfg; }

void AiBackend::fitWindow(const AiConfig& cfg, std::size_t tools_chars, const CancellationToken* cancel,
                          bool again) {
    m_requestOutputLimit = 0;
    m_compactStopped = false;
    if (!again) {
        // a new request: whether the one before it was compacted
        m_compactedPrev = m_compactedThis;
        m_compactedThis = false;
    }
    if (!cfg.compactInTurn() || m_compacting) return;
    const std::size_t window = cfg.contextWindow() > 0 ? static_cast<std::size_t>(cfg.contextWindow()) : 0;
    // what the next request holds: the last one's input as the provider
    // counted it and, at about four characters a token, what came since; with
    // no count, the whole of it so, its tools' definitions too
    auto estimate = [&](std::size_t chars) {
        if (m_lastInputTokens > 0 && m_sentChars > 0 && chars >= m_sentChars)
            return m_lastInputTokens + (chars - m_sentChars) / 4;
        return (chars + getSystemPrompt().size() + tools_chars) / 4;
    };
    std::size_t chars = tapto::history_chars(getHistory());
    if (window) {
        const std::size_t reply = static_cast<std::size_t>(std::max(cfg.maxOutputTokens(), 0));
        std::size_t input = estimate(chars);
        if (input + reply > window &&
            compactTurn(cfg,
                        "the next request (about " + std::to_string(input) + " tokens and a reply of " +
                            std::to_string(reply) + ") would not fit the context window of " + std::to_string(window),
                        cancel)) {
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

bool AiBackend::compactTurn(const AiConfig& cfg, const std::string& why, const CancellationToken* cancel) {
    m_compactStopped = false;
    if (!cfg.compactInTurn() || m_compacting) return false;
    if (cancel && cancel->check()) {
        m_compactStopped = true;
        return false;
    }
    // once for a request, and not for two in a row: it would only go round
    if (m_compactedThis || m_compactedPrev)
        throw std::runtime_error("The conversation outgrew the model's context window again right after it was "
                                 "compacted (" + why + "); the turn stops here instead of compacting it again.");
    const json before = getHistory();
    if (!before.is_array() || before.empty()) return false;
    const std::string task = tapto::task_of_seed(tapto::first_user_text(before));
    const std::size_t tokens_before = m_lastInputTokens;
    const std::size_t sent_before = m_sentChars;

    // the summary, quietly: a program showing replies as they stream does
    // not show this one (CompactCallback tells it a compaction happened)
    AiConfig quiet = cfg;
    quiet.setStreamCallback({});
    m_quiet = &quiet;
    m_compacting = true;
    std::string summary;
    try {
        const std::string prompt = "The conversation so far:\n\n" +
                                   tapto::transcript(buildTrimmedHistoryForSummary()) + "\n---\n\n" +
                                   tapto::kCompactPrompt;
        // its reply within what the window leaves, when it is known
        int reply = tapto::kCompactReplyTokens;
        if (cfg.contextWindow() > 0) {
            const long long left = static_cast<long long>(cfg.contextWindow()) -
                                   static_cast<long long>((prompt.size() + getSystemPrompt().size()) / 4);
            reply = static_cast<int>(std::max<long long>(tapto::kMinReplyTokens, std::min<long long>(reply, left)));
        }
        summary = requestOnce(prompt, reply, cancel);
    } catch (const std::exception& e) {
        mclog(std::string("[compact] the summary failed: ") + e.what() + "\n");
        summary.clear();
    }
    m_compacting = false;
    m_quiet = nullptr;
    const bool stopped = cancel && cancel->check();
    m_compactStopped = stopped;
    if (stopped || summary.find_first_not_of(" \t\r\n") == std::string::npos) {
        // the conversation as it was, its accounting too (the summary's
        // request had its own)
        m_lastInputTokens = tokens_before;
        m_sentChars = sent_before;
        mclog(std::string("[compact] ") + (stopped ? "stopped" : "no summary") +
              "; the conversation is kept as it was (" + why + ")\n");
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
    beginWith(tapto::compact_seed(task, tapto::task_of_seed(m_turnPrompt), summary, state));
    m_compactedThis = true;
    mclog("[compact] " + why + ": the conversation (about " + std::to_string(info.tokens_before) +
          " tokens) starts again from a " + std::to_string(summary.size()) + "-character summary\n");
    return true;
}

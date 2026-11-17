// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#pragma once

// Compaction inside a turn (AiConfig::setCompactInTurn). A program whose
// agents run long tool loops on their own (a server's) cannot type /compact
// between two requests: the loop is inside chat(). With it on, chat()
// compacts the conversation itself, as /compact does, when the next request
// would not fit the model's context window (AiConfig::contextWindow), or when
// the provider refused one as too long. The conversation then starts again
// from the task as it was first given (and the turn's own request, when that
// is another), a summary of the work so far and the state of the work now
// (the program's, from AiConfig::compactCallback: a working tree's changed
// files and diff), and the turn goes on.
//
// At most once for a request, and not for two requests in a row: a
// conversation that outgrows the window again straight after a compaction
// would only compact again and again, so the turn fails instead.

#include <cstddef>
#include <functional>
#include <string>

#include <nlohmann/json.hpp>

namespace tapto {

struct CompactInfo {
    std::string why;               // what made it compact
    std::size_t tokens_before = 0; // the conversation's estimated size then
    std::size_t summary_chars = 0;
};

// Told after a turn's conversation was summarized, before it starts again.
// Returns what the new conversation is told of the work's state now (e.g. a
// working tree's changed files and its diff), or "" for nothing.
using CompactCallback = std::function<std::string(const CompactInfo&)>;

// The reply limit of the summarizing request, whatever the configured one.
constexpr int kCompactReplyTokens = 8000;

// The request that asks for the summary, after the conversation's transcript.
extern const char* const kCompactPrompt;

// Whether a provider's error says the request was over the model's context
// length: a 400 or 413 whose text says so (vLLM's "maximum context length",
// OpenAI's context_length_exceeded, Anthropic's "prompt is too long",
// Gemini's input token count, ...).
bool is_context_overflow(const std::string& error);

// The first user message's text in a history of any dialect (a string
// content, Claude's text blocks, Gemini's text parts); a turn of tool results
// only is skipped. "" when there is none.
std::string first_user_text(const nlohmann::json& history);

// A history of any dialect as plain text, for the summarizer to read: who
// said what, the tools called with their arguments, and their results. A
// summary asked for this way is one user message, whatever the dialect: no
// tool blocks without tools, no two user turns in a row.
std::string transcript(const nlohmann::json& history);

// The conversation a compaction starts again from. `task` is the first user
// message (when that is itself an earlier compaction's, its task part);
// `turn`, the request of the turn being compacted, when that is another.
std::string compact_seed(const std::string& task, const std::string& turn, const std::string& summary,
                         const std::string& state);
std::string task_of_seed(const std::string& first_message);

// A history's size in characters as a model would read it: its text, with
// each image (a base64 payload) counted as a fixed size, not its bytes.
std::size_t history_chars(const nlohmann::json& history);

} // namespace tapto

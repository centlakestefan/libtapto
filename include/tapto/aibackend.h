// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#pragma once

#include <cstddef>
#include <optional>
#include <string>

#include <nlohmann/json.hpp>

class Context;

// Abstract interface every provider client implements. tapto-code is a chat
// client: chat() sends one user message and returns the model's text reply,
// running any tools the model calls along the way and retaining conversation
// history across calls for multi-turn dialogue.
class AiBackend {
public:
    virtual ~AiBackend() = default;

    virtual void setSystemPrompt(const std::string& systemPrompt) = 0;
    virtual const std::string& getSystemPrompt() const = 0;

    virtual void setModel(const std::string& model) = 0;
    virtual void setHost(const std::string& host) = 0;
    virtual void setApiKeyRef(const std::string& apiKey) = 0;
    virtual void setThinkingBudget(std::optional<int> budget) = 0;

    // Send one user message and return the model's text reply. Tools supplied
    // via context.tools are executed as the model requests them.
    virtual std::string chat(Context& context, const std::string& user_message) = 0;

    // Conversation-history management for context persistence across calls.
    virtual void start() = 0;
    virtual bool hasHistory() const = 0;
    virtual void loadHistory(const nlohmann::json& history) = 0;
    virtual nlohmann::json getHistory() const = 0;

    // Input tokens the provider reported for the most recent request (usage.
    // input_tokens / usageMetadata.promptTokenCount) — i.e. how full the
    // context window is right now. 0 until the first turn has run, or when a
    // provider does not report it.
    virtual std::size_t lastInputTokens() const = 0;

    // Reset the request accounting (start() re-clears the conversation and
    // beginWithSummary() replaces it with a /compact summary).
    virtual void resetTokenAccounting() { m_lastInputTokens = 0; }
    std::size_t m_lastInputTokens = 0;

    // Replace the conversation with a fresh one whose first user turn carries
    // a summary of the discussion up to this point (used by the /compact
    // command). Providers must format the seed message in their native shape.
    virtual void beginWithSummary(const std::string& summaryText) = 0;
};

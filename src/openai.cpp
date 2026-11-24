// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#include "tapto/openai.h"

#include <algorithm>
#include <chrono>
#include <iostream>
#include <optional>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "tapto/base64.h"
#include "tapto/compact.h"
#include "tapto/encoding.h"
#include "tapto/log.h"
#include "tapto/retry.h"
#include "tapto/stream.h"
#include "stream_post.h"
#include "tapto/tool_image.h"
#include "tapto/ui.h"
#include "tapto/usage.h"

using json = nlohmann::json;
namespace ui = tapto::ui;

namespace {

/// <summary>Strip Harmony / channel-style special tokens from user-visible
/// content. Declared here so extractReasoning can route its value through the
/// same scrub (reasoning_content can leak channel tokens just like content can
/// when the server's extractor doesn't run).</summary>
std::string stripChannelTokens(std::string text);

/// <summary>Field names carrying chain-of-thought on an assistant message.
/// There is no standard: vLLM, llama.cpp and sglang with the deepseek/qwen
/// templates use `reasoning_content`, while some gateways and newer builds use
/// a bare `reasoning`. Both are checked, in that order.</summary>
const char* const kReasoningFields[] = {"reasoning_content", "reasoning"};

/// <summary>Returns the assistant message's chain-of-thought as a string when
/// present and non-empty — scrubbed of channel-style tokens — otherwise an
/// empty string.</summary>
std::string extractReasoning(const json& message) {
    for (const char* field : kReasoningFields) {
        if (!message.contains(field) || message[field].is_null()) continue;
        if (!message[field].is_string()) continue;
        const std::string value = message[field].get<std::string>();
        if (!value.empty()) return stripChannelTokens(value);
    }
    return "";
}

/// <summary>Strip Harmony / channel-style special tokens from user-visible
/// content. When the inference server runs with `--reasoning-format none` (or
/// without a matching extractor for the model's chat template), tokens such
/// as `<|channel|>analysis<|message|>...<|end|>` leak into `content`
/// instead of being routed to `reasoning_content`. This is a defensive scrub;
/// the server-side extractor remains the correct fix when it works.</summary>
std::string stripChannelTokens(std::string text) {
    if (text.empty()) return text;

    // Drop reasoning channels entirely (analysis/thought blocks), up to the
    // next <|end|>, the next channel opening, or end of string. \|? makes the
    // pipe optional so we tolerate mangled variants like <channel>thought<message>.
    static const std::regex reasoningBlock(
        R"(<\|?channel\|?>\s*(?:analysis|thought)\s*<\|?message\|?>[\s\S]*?(?=<\|?end\|?>|<\|?channel\|?>|$))",
        std::regex::ECMAScript | std::regex::icase
    );
    text = std::regex_replace(text, reasoningBlock, "");

    // Strip stray channel/message/end and start-of-message markers that
    // remain (e.g. the wrappers around the `final` channel content).
    static const std::regex strayTokens(
        R"(<\|?(?:channel|message|end|start|im_start|im_end)\|?>)",
        std::regex::ECMAScript | std::regex::icase
    );
    text = std::regex_replace(text, strayTokens, "");

    // Trim leading/trailing whitespace left behind by the strips.
    auto first = text.find_first_not_of(" \t\r\n");
    auto last  = text.find_last_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    return text.substr(first, last - first + 1);
}

/// <summary>Returns the user-visible `content` of an assistant message, or an
/// empty string when absent/null/non-string. Strips Harmony channel tokens
/// (see stripChannelTokens) so callers don't have to.</summary>
std::string extractContent(const json& message) {
    if (!message.contains("content") || message["content"].is_null()) {
        return "";
    }
    if (!message["content"].is_string()) {
        return "";
    }
    return stripChannelTokens(message["content"].get<std::string>());
}

/// <summary>An assistant message as the conversation history keeps it. Its
/// chain of thought (`reasoning_content`) stays, so a program can show it
/// later (a /cot turned on, a resumed conversation); call_openai leaves it out
/// of every request (forRequest). A tool call whose arguments are not a JSON object (a reply cut off at the
/// output limit partway through them) is sent back with `{}`: llama.cpp
/// parses every call's arguments in the history to render its chat template
/// and refuses the whole request otherwise (HTTP 500, "Failed to parse tool
/// call arguments as JSON"), every retry alike. The tool result says what
/// went wrong.</summary>
json historyMessage(json message) {
    if (message.contains("tool_calls") && message["tool_calls"].is_array()) {
        for (json& call : message["tool_calls"]) {
            if (!call.is_object() || !call.contains("function") || !call["function"].is_object()) continue;
            json& fn = call["function"];
            bool ok = false;
            if (fn.contains("arguments") && fn["arguments"].is_string()) {
                const json parsed = json::parse(fn["arguments"].get<std::string>(), nullptr, false);
                ok = !parsed.is_discarded() && parsed.is_object();
            }
            if (!ok) fn["arguments"] = "{}";
        }
    }
    return message;
}

/// <summary>A history message as it is sent: without its chain of thought,
/// which some providers (DeepSeek's hosted API) refuse when it is sent back
/// and all of them would waste tokens reading.</summary>
json forRequest(const json& message) {
    if (!message.is_object()) return message;
    bool has = false;
    for (const char* field : kReasoningFields) has = has || message.contains(field);
    if (!has) return message;
    json out = message;
    for (const char* field : kReasoningFields) out.erase(field);
    return out;
}

} // namespace

OpenAIClient::OpenAIClient(const AiConfig* config, const std::string& url, const std::string& model, const std::string& apiKey)
    : m_config(config), m_model(model), m_apiKeyRef(apiKey) {
    m_url = url;

    mclog("OpenAIClient initialized with url=" + m_url + "\n");
}

/// <summary>Initializes the persistent client with proper timeout and keep-alive settings.</summary>
void OpenAIClient::init_api_client() {
    mclog("Initializing API client connection to " + m_url + "\n");

    m_api_client = std::make_unique<httplib::Client>(m_url);
    // Certificate verification only applies to https endpoints; skip it for plain http.
    if (m_url.rfind("https://", 0) == 0) {
        m_api_client->enable_server_certificate_verification(true);
    }

    m_api_client->set_connection_timeout(m_config->connectionTimeoutSeconds());
    m_api_client->set_read_timeout(m_config->readTimeoutSeconds());
    m_api_client->set_keep_alive(true);

    mclog("API client initialized with keep-alive enabled\n");
}

/// <summary>Returns the configured OpenAI API key.</summary>
std::string OpenAIClient::getApiKey() {
    if (!m_apiKeyRef.empty()) {
        return m_apiKeyRef;
    }
    throw std::runtime_error("OpenAI API key is not set");
}

/// <summary>Makes API call to OpenAI with retry logic.</summary>
json OpenAIClient::call_openai(const std::string& user_message, const json& tools, const json& conversation_history,
                               const CancellationToken* cancel) {
    // Build messages array
    json messages = json::array();

    // Add system message first (OpenAI puts system as first message)
    if (!m_systemPrompt.empty()) {
        messages.push_back({
            {"role", "system"},
            {"content", m_systemPrompt}
        });
    }

    // Add conversation history, its chain of thought left out
    for (const auto& msg : conversation_history) {
        messages.push_back(forRequest(msg));
    }

    // Add new user message if provided
    if (!user_message.empty()) {
        messages.push_back({
            {"role", "user"},
            {"content", user_message}
        });
    }

    // Build request body
    json request_body = {
        {"model", m_model},
        {"max_tokens", outputLimit(*m_config)},
        {"messages", messages}
    };

    // Reasoning-effort hint for the reasoning models (gpt-5, o-series) and for
    // OpenAI-compatible servers that accept the same field. Sent only when
    // configured, and verbatim: which values an endpoint takes is the
    // endpoint's business, and a rejected one comes back as its own API error.
    if (!m_config->openaiReasoningEffort().empty()) {
        request_body["reasoning_effort"] = m_config->openaiReasoningEffort();
    }

    // Add tools if provided
    if (!tools.empty()) {
        request_body["tools"] = tools;
        request_body["tool_choice"] = "auto";
    }

    // Provider-level extended-thinking override. OpenAI-compatible servers
    // that support a thinking toggle (Qwen3, GLM-4.5, etc.) read it from
    // chat_template_kwargs.enable_thinking. The toggle is boolean — the
    // numeric budget has no place in this protocol, so any value > 0 just
    // means "on".
    if (m_thinkingBudget.has_value()) {
        request_body["chat_template_kwargs"] = {
            {"enable_thinking", m_thinkingBudget.value() > 0}
        };
    }

    // Asked as a stream, the reply comes back in pieces, which post_stream
    // puts back together. include_usage asks for the token counts, which a
    // stream otherwise leaves out; a server that ignores it reports none.
    const bool streaming = m_config->stream();
    if (streaming) {
        request_body["stream"] = true;
        request_body["stream_options"] = {{"include_usage", true}};
    }
    const std::string body = request_body.dump();

    std::string api_key = getApiKey();

    // Set headers
    httplib::Headers headers = {
        {"Authorization", "Bearer " + api_key},
        {"Content-Type", "application/json"}
    };
    if (!m_config->userAgent().empty()) headers.emplace("User-Agent", m_config->userAgent());

    const int retry_for = m_config->retryForSeconds();
    tapto::RetryBudget connection(MAX_CONNECTION_RETRIES, CONNECTION_BACKOFF_BASE, CONNECTION_BACKOFF_MAX, retry_for);
    tapto::RetryBudget rate_limit(MAX_RATE_LIMIT_RETRIES, RATE_LIMIT_BACKOFF_BASE, RATE_LIMIT_BACKOFF_MAX, retry_for);
    tapto::RetryBudget server_error(MAX_SERVER_ERROR_RETRIES, SERVER_ERROR_BACKOFF_BASE, SERVER_ERROR_BACKOFF_MAX,
                                    retry_for);

    for (;;) {
        tapto::StreamOutcome streamed;
        tapto::OpenAIStreamAccumulator acc;
        auto res = streaming ? tapto::post_stream(*m_api_client, "/v1/chat/completions", headers, body,
                                                  streamConfig(*m_config), cancel, acc, streamed)
                             : m_api_client->Post("/v1/chat/completions", headers, body, "application/json");

        // Stopped by the user partway through: what arrived is the reply.
        if (streamed.cancelled) {
            mclog("Reply stopped by the user partway through\n");
            return streamed.response;
        }

        // Handle connection errors
        if (!res) {
            auto error = res.error();
            std::string error_msg = httplib::to_string(error);

            // Part of the reply is already on the user's screen. Asking again
            // would show it a second time, and as a different reply.
            if (streamed.shown && !m_config->retryLostReply()) {
                mclog("Connection lost partway through a streamed reply: " + error_msg + "\n");
                throw std::runtime_error("The connection was lost partway through the reply: " + error_msg);
            }

            mclog("Connection failed (retry " + std::to_string(connection.retry() + 1) + "): " + error_msg + "\n");

            // Waits 2, 4, 8, 16, 32 seconds: five of them, or for as long as retryForSeconds
            if (!connection.next()) {
                mclog("Exceeded maximum connection retries\n");
                throw std::runtime_error("Connection failed after " + connection.spent() + ": " + error_msg);
            }

            // Reinitialize connection on connection failure
            mclog("Reinitializing API client connection...\n");
            init_api_client();

            mclog("Retrying in " + std::to_string(connection.wait_seconds()) + " seconds...\n");
            tapto::report_retry(m_config->retryCallback(), "connection failed: " + error_msg, connection);
            if (!tapto::retry_wait(connection.wait_seconds(), cancel)) return acc.response(/*interrupted=*/true);
            continue;
        }

        // Reset connection retry counter on successful connection
        connection.reset();

        // Handle HTTP status codes
        int status = res->status;

        // Success
        if (status == 200) {
            json resp;
            if (streamed.handled) {
                resp = streamed.response;
            } else {
                resp = json::parse(res->body);
                // Asked for a stream, answered whole: shown whole.
                if (streaming && resp.contains("choices") && resp["choices"].is_array() &&
                    !resp["choices"].empty()) {
                    const json message = resp["choices"][0].value("message", json::object());
                    tapto::show_whole(streamConfig(*m_config).streamCallback(), extractReasoning(message),
                                      extractContent(message));
                }
            }
            // How the provider names the input consumption varies: OpenAI uses
            // usage.input_tokens, but most OpenAI-compatible servers (vLLM,
            // Ollama, LM Studio, ...) use usage.prompt_tokens. Accept both.
            json usage = resp.value("usage", json::object());
            if (usage.contains("input_tokens")) {
                m_lastInputTokens = usage.at("input_tokens").get<std::size_t>();
            } else if (usage.contains("prompt_tokens")) {
                m_lastInputTokens = usage.at("prompt_tokens").get<std::size_t>();
            } else {
                m_lastInputTokens = 0;
                mclog("[usage] provider did not report input tokens "
                      "(no usage.input_tokens / usage.prompt_tokens)\n");
            }
            // Logged in full mainly to make image handling observable. A vision
            // model resizes an image to its own pixel budget before tokenising
            // it, and the token count is the only report of what it decided:
            // the difference this call makes to prompt_tokens is the image's
            // cost.
            if (usage.is_object() && !usage.empty()) {
                mclog("usage: prompt=" + std::to_string(usage.value("prompt_tokens", 0)) +
                      " completion=" + std::to_string(usage.value("completion_tokens", 0)) +
                      " total=" + std::to_string(usage.value("total_tokens", 0)) + "\n");
            }
            tapto::report_usage(m_config->usageCallback(), "openai", m_model, resp);
            return resp;
        }

        // Rate limiting (429)
        if (status == 429) {
            int wait_seconds = 0;

            // Try to parse retry-after header with error handling
            if (res->has_header("retry-after")) {
                try {
                    wait_seconds = std::stoi(res->get_header_value("retry-after"));
                }
                catch (const std::exception& e) {
                    std::ostringstream err;
                    err << "Failed to parse retry-after header: " << e.what() << "\n";
                    mclog(err.str());
                    wait_seconds = 0;
                }
            }

            // The retry-after when there is one, else doubling waits; capped
            // either way so a hostile/buggy retry-after can't make us sleep
            // indefinitely.
            if (!rate_limit.next(wait_seconds)) {
                mclog("Exceeded maximum rate limit retries (" + rate_limit.spent() + ")\n");
                throw std::runtime_error("Exceeded maximum rate limit retries (" + rate_limit.spent() + ")");
            }

            mclog("Rate limited (retry " + std::to_string(rate_limit.retry()) + "). Waiting " +
                  std::to_string(rate_limit.wait_seconds()) + " seconds before retry\n");

            tapto::report_retry(m_config->retryCallback(), "rate limited (429)", rate_limit);
            if (!tapto::retry_wait(rate_limit.wait_seconds(), cancel)) return acc.response(/*interrupted=*/true);
            continue;
        }

        // Client errors (4xx) - generally not retryable
        if (status >= 400 && status < 500) {
            std::string error_detail = res->body.length() > 500 ? res->body.substr(0, 500) + "..." : res->body;
            std::ostringstream log_msg;
            log_msg << "Client error " << status << ": " << error_detail << "\n";
            mclog(log_msg.str());

            std::ostringstream exception_msg;
            switch (status) {
            case 400:
                exception_msg << "Bad Request (400): Invalid request format or parameters - " << error_detail;
                break;
            case 401:
                exception_msg << "Unauthorized (401): Invalid or missing API key - " << error_detail;
                break;
            case 403:
                exception_msg << "Forbidden (403): Access denied - " << error_detail;
                break;
            case 404:
                exception_msg << "Not Found (404): Endpoint not found - " << error_detail;
                break;
            default:
                exception_msg << "Client error (" << status << "): " << error_detail;
                break;
            }
            // A per-prompt image cap is a server-side limit with a client-side
            // remedy, and the server's wording does not say so.
            if (error_detail.find("image") != std::string::npos &&
                (error_detail.find("At most") != std::string::npos ||
                 error_detail.find("limit") != std::string::npos)) {
                exception_msg << "\nThe server caps how many images one prompt may carry. Lower "
                                 "'keep-recent-images' in the tapto config to at or below that "
                                 "number (it is currently "
                              << m_config->keepRecentImages()
                              << "), or restart the server with a higher "
                                 "--limit-mm-per-prompt image=N.";
            }
            throw std::runtime_error(exception_msg.str());
        }

        // Server errors (5xx) - can be retried...
        if (status >= 500 && status < 600) {
            // ...unless the body says the request itself is the problem.
            //
            // OpenAI-compatible servers do not all classify errors the same
            // way: llama.cpp answers "image input is not supported" with a 500
            // even though it is a permanent property of the loaded model, not a
            // transient fault. Retrying that five times with backoff wastes
            // over a minute and buries the one line that explains the failure.
            {
                std::string lowered = res->body;
                std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                static const char* kPermanent[] = {
                    "not supported", "unsupported", "invalid_request", "does not support",
                };
                for (const char* marker : kPermanent) {
                    if (lowered.find(marker) != std::string::npos) {
                        std::string detail = res->body.length() > 500
                                                 ? res->body.substr(0, 500) + "..." : res->body;
                        mclog("Permanent server error, not retrying: " + detail + "\n");
                        throw std::runtime_error(
                            "Server rejected the request (" + std::to_string(status) +
                            "), and the error is not transient so it was not retried: " + detail);
                    }
                }
            }

            int wait_seconds = 0;

            // For 503 Service Unavailable, respect retry-after header
            if (status == 503 && res->has_header("retry-after")) {
                try {
                    wait_seconds = std::stoi(res->get_header_value("retry-after"));
                }
                catch (const std::exception& e) {
                    std::ostringstream err;
                    err << "Failed to parse retry-after header: " << e.what() << "\n";
                    mclog(err.str());
                    wait_seconds = 0;
                }
            }

            // The retry-after when there is one, else doubling waits; capped
            // either way against a hostile retry-after.
            if (!server_error.next(wait_seconds)) {
                std::string error_detail = res->body.length() > 500 ? res->body.substr(0, 500) + "..." : res->body;
                mclog("Exceeded maximum server error retries (" + server_error.spent() + ")\n");
                throw std::runtime_error("Server error (" + std::to_string(status) + ") after " +
                                         server_error.spent() + ": " + error_detail);
            }

            std::string error_msg;
            switch (status) {
            case 500: error_msg = "Internal Server Error"; break;
            case 502: error_msg = "Bad Gateway"; break;
            case 503: error_msg = "Service Unavailable"; break;
            case 504: error_msg = "Gateway Timeout"; break;
            default: error_msg = "Server Error"; break;
            }

            mclog(error_msg + " (" + std::to_string(status) + ") - retry " + std::to_string(server_error.retry()) +
                  ". Retrying in " + std::to_string(server_error.wait_seconds()) + " seconds\n");

            tapto::report_retry(m_config->retryCallback(), error_msg + " (" + std::to_string(status) + ")",
                                server_error);
            if (!tapto::retry_wait(server_error.wait_seconds(), cancel)) return acc.response(/*interrupted=*/true);
            continue;
        }

        // Unknown status code
        std::string error_detail = res->body.length() > 500 ? res->body.substr(0, 500) + "..." : res->body;
        mclog("Unexpected HTTP status " + std::to_string(status) + ": " + error_detail + "\n");
        throw std::runtime_error("Unexpected HTTP status " + std::to_string(status) + ": " + error_detail);
    }
}

/// <summary>Sends one user message and returns OpenAI's text reply, running any
/// tools the model calls along the way.</summary>
std::string OpenAIClient::chat(Context& context, const std::string& user_message) {
    beginTurn(user_message);

    m_tool_registry.clear();
    m_tools.clear();

    // Wrap all tools to bind the context
    for (const auto& tool : context.tools) {
        auto executor = tool.executor;
        m_tool_registry[tool.name] = [executor, spec = tool, &context](const json& input) {
            if (std::string wrong = tapto::misnamed_arguments(spec, input); !wrong.empty()) return wrong;
            return executor(context, input);
        };
        m_tools.push_back(tool);
    }

    mclog("Start " + user_message + " ===\n");

    // Convert tools to OpenAI format
    json tools = json::array();
    for (const auto& tool_spec : m_tools) {
        json tool_def = tool_definition_to_json(tool_spec, ToolFormat::OpenAI);

        // OpenAI expects tools in a specific format with "type": "function"
        json openai_tool = {
            {"type", "function"},
            {"function", tool_def}
        };

        tools.push_back(openai_tool);
    }

    int iteration = 0;
    const int max_iterations = m_config->maxToolIterations();

    if (!m_api_client) init_api_client();

    // Add the user message to persistent history. Sanitize on entry: a prompt
    // that carries invalid UTF-8 (an accented word typed on a console whose
    // code page mangled it, a BOM-marked paste) would abort the first request
    // that serializes it with json.exception.type_error.316, so the turn dies
    // before the model ever sees it.
    if (!user_message.empty()) {
        m_conversation_history.push_back({
            {"role", "user"},
            {"content", tapto::sanitizeUserMessage(user_message)}
        });
    }

    // Each request of the turn: kept within the context window, and asked
    // again once compacted when the provider says it was over (compact.h).
    // None: stopped while a compaction was asked for.
    const std::size_t tools_chars = tools.dump().size();
    auto send = [&]() -> std::optional<json> {
        fitWindow(*m_config, tools_chars, context.cancel);
        if (m_compactStopped) return std::nullopt;
        for (;;) {
            try {
                return call_openai("", tools, m_conversation_history, context.cancel);
            } catch (const std::runtime_error& e) {
                // refused as too long: compacted and asked again; refused
                // again, compactTurn says it would go round
                if (!tapto::is_context_overflow(e.what())) throw;
                if (!compactTurn(*m_config, std::string("the provider said the request was too long: ") + e.what(),
                                 context.cancel)) {
                    if (m_compactStopped) return std::nullopt;
                    throw;
                }
                fitWindow(*m_config, tools_chars, context.cancel, true);
            }
        }
    };

    ui::set_status("Thinking...", 0, max_iterations);
    json response;
    {
        auto first = send();
        if (!first) {
            ui::end_status();
            return std::string();
        }
        response = *first;
    }
    // the latest round's calls all have their results: a stop now leaves
    // nothing to answer after the loop (it would answer them twice)
    bool answered = false;
    if (!response.contains("choices") || response["choices"].empty()) {
        throw std::runtime_error("Invalid OpenAI response: " + response.dump());
    }

    auto choice = response["choices"][0];
    auto message = choice["message"];
    m_conversation_history.push_back(historyMessage(message));

    // Tool loop: keep going while the model requests tools. Terminates as soon
    // as the model replies without tool_calls.
    while (message.contains("tool_calls") && !message["tool_calls"].empty() && iteration < max_iterations) {
        // Check for user interruption (ESC key).
        if (context.cancel && context.cancel->check()) break;

        iteration++;
        mclog("=== Iteration " + std::to_string(iteration) + " ===\n");

        // Shown already when the program takes the reply as it streams.
        const bool shown = m_config->showsStream();
        {
            std::string cot = extractReasoning(message);
            if (!cot.empty()) {
                mclog("Assistant CoT: " + cot + "\n");
                if (!shown) ui::emit_intermediate(cot, /*is_reasoning=*/true, m_config->printCot());
            }
        }
        {
            std::string text = extractContent(message);
            if (!text.empty()) {
                mclog("Assistant text: " + text + "\n");
                if (!shown) ui::emit_intermediate(text, /*is_reasoning=*/false, m_config->printCot());
            }
        }

        // Process each tool call
        // Images produced by tools this round. They cannot travel inside the
        // tool results: an OpenAI `role: "tool"` message carries text only.
        // They also cannot be interleaved between tool results, because every
        // tool_call in the assistant message must be answered before any other
        // message appears. So they are collected here and delivered as one
        // user turn once the whole round is answered.
        std::vector<tapto::ToolImage> pending_images;

        for (const auto& tool_call : message["tool_calls"]) {
            std::string tool_id = tool_call["id"];
            std::string tool_name = tool_call["function"]["name"];

            json tool_input;
            std::string result;
            bool args_parsed = false;
            try {
                tool_input = json::parse(tool_call["function"]["arguments"].get<std::string>());
                args_parsed = true;
            }
            catch (const std::exception& e) {
                std::string raw_args;
                try {
                    raw_args = tool_call["function"]["arguments"].get<std::string>();
                }
                catch (...) {
                    raw_args = tool_call["function"]["arguments"].dump();
                }
                // The start of them only: a call cut off at the output limit
                // carries a whole file's worth, which would fill the context.
                constexpr std::size_t kShownArgs = 1000;
                std::string shown_args = raw_args;
                if (shown_args.size() > kShownArgs) {
                    std::size_t cut = kShownArgs;
                    while (cut > 0 && (static_cast<unsigned char>(shown_args[cut]) & 0xC0) == 0x80) --cut;
                    shown_args = shown_args.substr(0, cut) + "... (" + std::to_string(raw_args.size()) +
                                 " characters in all)";
                }
                const bool cut_off = choice.value("finish_reason", std::string()) == "length";
                // the parser's message quotes the last token read: the whole cut-off string
                std::string why = e.what();
                if (why.size() > 300) {
                    std::size_t at = 300;
                    while (at > 0 && (static_cast<unsigned char>(why[at]) & 0xC0) == 0x80) --at;
                    why = why.substr(0, at) + "...";
                }
                result = "ERROR: Tool call arguments are not valid JSON: " + why +
                        "\nReceived arguments: " + shown_args +
                        (cut_off ? "\nYour reply reached the output limit (max output tokens) in the middle of "
                                   "this call, so its arguments were cut off and it did not run. Make the call "
                                   "smaller: write a large file in parts, creating it with the first part and "
                                   "adding the rest with further edits."
                                 : "\nPlease retry this tool call with a valid JSON object as the arguments.");
                mclog("Tool argument parse failure for '" + tool_name + "': " + e.what() + "\n");
            }

            if (!args_parsed) {
                m_conversation_history.push_back({
                    {"role", "tool"},
                    {"tool_call_id", tool_id},
                    {"content", result}
                });
                continue;
            }

            ui::set_status(getToolDisplayName(context.tools, tool_name, tool_input), iteration, max_iterations);
            mclog("Executing tool: " + tool_name + "\n");
            mclog("Input: " + tool_input.dump(2) + "\n");

            auto it = m_tool_registry.find(tool_name);
            if (context.cancel && context.cancel->check()) {
                // Stopped during an earlier call of this batch: the rest are
                // answered, not run.
                result = "Tool not run: the turn was stopped before it ran (interrupted).";
            } else if (it != m_tool_registry.end()) {
                try {
                    result = tapto::sanitizeToolResult(it->second(tool_input), tool_name);
                }
                catch (const tapto::ConnectionLost&) {
                    // Not answerable by the model: every later call fails the
                    // same way. End the turn instead of spending a round trip
                    // on each retry.
                    throw;
                }
                catch (const std::exception& e) {
                    result = "ERROR: Tool execution failed: " + std::string(e.what());
                    mclog("Tool execution exception: " + std::string(e.what()) + "\n");
                }
            }
            else {
                result = formatUnknownToolError(tool_name, m_tool_registry);
                mclog("Unknown tool requested: " + tool_name + "\n");
            }

            ui::commit_status(); // lock the tool line into the scroll buffer

            m_conversation_history.push_back({
                {"role", "tool"},
                {"tool_call_id", tool_id},
                {"content", result}
            });

            tapto::ToolImage image;
            if (tapto::takeToolImage(context, image)) {
                pending_images.push_back(std::move(image));
            }
        }

        // Every tool_call is now answered, so it is safe to add the images.
        if (!pending_images.empty()) {
            json parts = json::array();
            for (const auto& image : pending_images) {
                if (!image.label.empty()) {
                    parts.push_back({{"type", "text"}, {"text", image.label + ":"}});
                }
                parts.push_back({
                    {"type", "image_url"},
                    {"image_url", {{"url", "data:image/png;base64," +
                                           tapto::base64Encode(image.png)}}}
                });
            }
            m_conversation_history.push_back({{"role", "user"}, {"content", parts}});
            mclog("Attached " + std::to_string(pending_images.size()) +
                  " image(s) as a user turn\n");
        }

        answered = true;

        // Check for user interruption before the (potentially slow) API call.
        if (context.cancel && context.cancel->check()) break;

        // See claude.cpp: unbounded image history ends in HTTP 413.
        if (m_config->keepRecentImages() > 0) {
            const size_t pruned = tapto::pruneHistoryImages(
                m_conversation_history, static_cast<size_t>(m_config->keepRecentImages()));
            if (pruned > 0) {
                mclog("Pruned " + std::to_string(pruned) + " older image(s) from history\n");
            }
        }

        ui::set_status("Thinking...", iteration, max_iterations);
        auto next = send();
        if (!next) break;
        response = *next;
        answered = false;
        if (!response.contains("choices") || response["choices"].empty()) {
            throw std::runtime_error("Invalid OpenAI response: " + response.dump());
        }

        choice = response["choices"][0];
        message = choice["message"];
        m_conversation_history.push_back(historyMessage(message));
    }

    if (iteration >= max_iterations) {
        mclog("Warning: Reached maximum iterations\n");
    }
    bool user_cancelled = (context.cancel && context.cancel->cancelled());
    if (user_cancelled) {
        mclog("Cancelled by user (ESC)\n");
    }

    // If we stopped with unanswered tool calls (iteration cap or user cancel),
    // answer them so the conversation stays valid on the next turn.
    if (!answered && message.contains("tool_calls") && !message["tool_calls"].empty()) {
        std::string reason = user_cancelled
            ? "Tool not run: the turn was stopped before it ran (interrupted, or ended by an earlier call)."
            : "Tool not run: iteration limit reached.";
        for (const auto& tc : message["tool_calls"]) {
            m_conversation_history.push_back({
                {"role", "tool"},
                {"tool_call_id", tc.value("id", std::string())},
                {"content", reason}
            });
        }
    }

    mclog("=== Final Response === " + choice.value("finish_reason", "unknown") + "\n");

    ui::end_status();

    // The closing message never passes through the loop above, because the loop
    // exits precisely when a message arrives without tool calls -- so the one
    // thing missing from the trace was the model's summary of what it had just
    // done, which is the part a human reads first. Logged here rather than at
    // the top of the loop so it also covers a turn stopped by the iteration
    // cap, whose message never reached the loop body either.
    {
        const std::string cot = extractReasoning(message);
        if (!cot.empty()) mclog("Assistant CoT: " + cot + "\n");
        const std::string text = extractContent(message);
        if (!text.empty()) mclog("Assistant text: " + text + "\n");
    }

    // Collect the assistant's final text reply (falling back to reasoning
    // content for reasoning models that emit only that). Skip the fallback on
    // a turn that ended mid-tool-call (iteration cap or user cancel): the CoT
    // was already surfaced to the transcript in the loop, so repeating it here
    // as the "final reply" would print the same block twice.
    std::string reply = extractContent(message);
    const bool stoppedMidToolCall =
        message.contains("tool_calls") && !message["tool_calls"].empty();
    if (reply.empty() && !stoppedMidToolCall) {
        reply = extractReasoning(message);
    }
    if (choice.value("finish_reason", std::string()) == "length") {
        reply += "\n[truncated: hit max output tokens - raise max-output-tokens]";
    }
    return reply;
}

/// <summary>Starts a new conversation by clearing the conversation history.</summary>
void OpenAIClient::start() {
    m_conversation_history = json::array();
    resetTokenAccounting();
    mclog("Started new conversation (history cleared)\n");
}

/// <summary>Checks if conversation history exists.</summary>
bool OpenAIClient::hasHistory() const {
    return !m_conversation_history.empty();
}

/// <summary>Loads conversation history from stored format.</summary>
void OpenAIClient::loadHistory(const json& history) {
    if (!history.is_array()) {
        mclog("ERROR: Invalid history format - expected array\n");
        return;
    }

    m_conversation_history = history;
    mclog("Loaded conversation history with " + std::to_string(history.size()) + " messages\n");
}

/// <summary>Gets the current conversation history.</summary>
json OpenAIClient::getHistory() const {
    return m_conversation_history;
}

/// <summary>Starts a new conversation seeded with a summary of the previous one (/compact).</summary>
void OpenAIClient::beginWithSummary(const std::string& summaryText) {
    beginWith("(The conversation prior to this point has been summarized for context):\n" + summaryText);
    mclog("Started conversation seeded with summary of previous discussion");
}

void OpenAIClient::beginWith(const std::string& text) {
    resetTokenAccounting();
    m_conversation_history = json::array();
    m_conversation_history.push_back({{"role", "user"}, {"content", text}});
}

std::string OpenAIClient::requestOnce(const std::string& prompt, int max_output_tokens,
                                   const CancellationToken* cancel) {
    if (!m_api_client) init_api_client();
    m_requestOutputLimit = max_output_tokens;
    json resp;
    try {
        resp = call_openai(prompt, json::array(), json::array(), cancel);
    } catch (...) {
        m_requestOutputLimit = 0;
        throw;
    }
    m_requestOutputLimit = 0;
    if (!resp.contains("choices") || !resp["choices"].is_array() || resp["choices"].empty()) return {};
    const json message = resp["choices"][0].value("message", json::object());
    std::string text = extractContent(message);
    if (text.empty()) text = extractReasoning(message);
    return text;
}

/// <summary>Sets the model for OpenAI client.</summary>
void OpenAIClient::setModel(const std::string& model) {
    m_model = model;
    mclog("OpenAIClient model updated to: " + model + "\n");
}

/// <summary>Sets the host URL for OpenAI client and resets the API client.</summary>
void OpenAIClient::setHost(const std::string& host) {
    m_url = host;
    m_api_client.reset();  // Reset client to force re-initialization with new URL
    mclog("OpenAIClient host updated to: " + host + " (API client reset)\n");
}

/// <summary>Sets the API key for OpenAI client.</summary>
void OpenAIClient::setApiKeyRef(const std::string& apiKey) {
    m_apiKeyRef = apiKey;
    mclog("OpenAIClient API key updated\n");
}

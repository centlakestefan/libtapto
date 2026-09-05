// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

// Unit tests for the parts of libtapto that need no provider on the other end:
// the config store, secret references, UTF-8 sanitising, tool images and the
// tool display hook. Plain assertions; ctest runs the binary.

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#include <nlohmann/json.hpp>

#include "tapto/base64.h"
#include "tapto/config.h"
#include "tapto/context.h"
#include "tapto/encoding.h"
#include "tapto/secret.h"
#include "tapto/tool_image.h"
#include "tapto/tool_registry.h"

using nlohmann::json;
namespace fs = std::filesystem;

namespace {

int g_failures = 0;

#define CHECK(cond)                                                              \
    do {                                                                         \
        if (!(cond)) {                                                           \
            std::cerr << __FILE__ << ":" << __LINE__ << ": CHECK failed: " #cond \
                      << "\n";                                                   \
            ++g_failures;                                                        \
        }                                                                        \
    } while (0)

#define CHECK_EQ(a, b)                                                           \
    do {                                                                         \
        const auto _a = (a);                                                     \
        const auto _b = (b);                                                     \
        if (!(_a == _b)) {                                                       \
            std::cerr << __FILE__ << ":" << __LINE__ << ": CHECK_EQ failed: "    \
                      << #a << " == " << #b << "  (" << _a << " vs " << _b       \
                      << ")\n";                                                  \
            ++g_failures;                                                        \
        }                                                                        \
    } while (0)

fs::path scratch_file(const char* name) {
    return fs::temp_directory_path() / ("libtapto-test-" + std::string(name));
}

// --- config -----------------------------------------------------------------

void test_config_roundtrip() {
    const fs::path path = scratch_file("config");
    fs::remove(path);

    tapto::Config missing = tapto::Config::load(path);
    CHECK(missing.entries().empty());

    tapto::Config cfg;
    cfg.set("provider", "qwen36");
    cfg.set("qwen36-provider-type", "openai");
    cfg.set("qwen36-provider-type", "openai"); // idempotent
    cfg.set("qwen36-model", "Qwen3-VL-30B");
    CHECK_EQ(cfg.entries().size(), std::size_t(3));
    cfg.save(path);

    tapto::Config back = tapto::Config::load(path);
    CHECK_EQ(back.get("provider").value_or(""), std::string("qwen36"));
    CHECK_EQ(back.get("qwen36-model").value_or(""), std::string("Qwen3-VL-30B"));
    CHECK(!back.get("nope").has_value());
    CHECK(back.unset("qwen36-model"));
    CHECK(!back.unset("qwen36-model"));
    CHECK_EQ(back.entries().size(), std::size_t(2));

    fs::remove(path);
}

// --- secret -----------------------------------------------------------------

void test_secret_literal_and_env() {
    tapto::Secret literal = tapto::resolve_secret("sk-plain");
    CHECK(literal.ok());
    CHECK_EQ(literal.value, std::string("sk-plain"));
    CHECK(literal.error.empty());

#ifdef _WIN32
    _putenv_s("LIBTAPTO_TEST_KEY", "from-env");
#else
    setenv("LIBTAPTO_TEST_KEY", "from-env", 1);
#endif
    tapto::Secret env = tapto::resolve_secret("env:LIBTAPTO_TEST_KEY");
    CHECK(env.ok());
    CHECK_EQ(env.value, std::string("from-env"));

    tapto::Secret unset = tapto::resolve_secret("env:LIBTAPTO_TEST_KEY_THAT_IS_NOT_SET");
    CHECK(!unset.ok());
    CHECK(!unset.error.empty());
}

// --- encoding ---------------------------------------------------------------

void test_sanitize_utf8() {
    CHECK_EQ(tapto::sanitizeUtf8("plain ascii"), std::string("plain ascii"));
    CHECK_EQ(tapto::sanitizeUtf8("h\xC3\xA4r"), std::string("h\xC3\xA4r")); // "här"

    // A lone continuation byte becomes U+FFFD and the rest survives.
    const std::string bad = "a\x80z";
    const std::string clean = tapto::sanitizeUtf8(bad);
    CHECK_EQ(clean, std::string("a\xEF\xBF\xBDz"));

    // The result always serialises.
    bool threw = false;
    try {
        (void)json(tapto::sanitizeUtf8("\xFF\xFE")).dump();
    } catch (...) {
        threw = true;
    }
    CHECK(!threw);
}

// --- base64 -----------------------------------------------------------------

void test_base64() {
    CHECK_EQ(tapto::base64Encode({}), std::string(""));
    CHECK_EQ(tapto::base64Encode({'f'}), std::string("Zg=="));
    CHECK_EQ(tapto::base64Encode({'f', 'o'}), std::string("Zm8="));
    CHECK_EQ(tapto::base64Encode({'f', 'o', 'o'}), std::string("Zm9v"));
    CHECK_EQ(tapto::base64Encode({'f', 'o', 'o', 'b', 'a', 'r'}), std::string("Zm9vYmFy"));
}

// --- tool images ------------------------------------------------------------

void test_tool_image_context() {
    Context ctx;
    tapto::ToolImage out;
    CHECK(!tapto::takeToolImage(ctx, out));

    tapto::ToolImage in;
    in.png = {1, 2, 3};
    in.width = 4;
    in.height = 5;
    in.label = "shot";
    tapto::putToolImage(ctx, in);
    CHECK(tapto::takeToolImage(ctx, out));
    CHECK_EQ(out.png.size(), std::size_t(3));
    CHECK_EQ(out.label, std::string("shot"));
    // Taken once: a stale image must never attach to a later result.
    CHECK(!tapto::takeToolImage(ctx, out));

    // An empty image is "no image".
    tapto::putToolImage(ctx, tapto::ToolImage{});
    CHECK(!tapto::takeToolImage(ctx, out));
}

json claude_image_msg() {
    return json{{"role", "user"},
                {"content", json::array({
                     json{{"type", "tool_result"}, {"tool_use_id", "x"},
                          {"content", json::array({
                               json{{"type", "text"}, {"text", "ok"}},
                               json{{"type", "image"},
                                    {"source", {{"type", "base64"}, {"media_type", "image/png"}, {"data", "AAAA"}}}}})}}})}};
}

void test_prune_history_images() {
    // No images: nothing to prune, nothing to cache around.
    json plain = json::array({json{{"role", "user"}, {"content", "hi"}},
                              json{{"role", "assistant"}, {"content", "hello"}}});
    CHECK_EQ(tapto::pruneHistoryImages(plain, 3), std::size_t(0));
    CHECK_EQ(tapto::firstLiveImageMessage(plain), plain.size());

    // Four images, keep two: the oldest two become placeholders, and the
    // first live image is then at index 2.
    json history = json::array({claude_image_msg(), claude_image_msg(),
                                claude_image_msg(), claude_image_msg()});
    CHECK_EQ(tapto::firstLiveImageMessage(history), std::size_t(0));
    CHECK_EQ(tapto::pruneHistoryImages(history, 2), std::size_t(2));
    CHECK_EQ(tapto::firstLiveImageMessage(history), std::size_t(2));
    CHECK_EQ(history[0]["content"][0]["content"][1]["type"].get<std::string>(), std::string("text"));
    CHECK_EQ(history[3]["content"][0]["content"][1]["type"].get<std::string>(), std::string("image"));

    // Pruning again changes nothing.
    CHECK_EQ(tapto::pruneHistoryImages(history, 2), std::size_t(0));

    // Gemini shape gets the Gemini placeholder.
    json gemini = json::array({json{{"role", "user"},
                                    {"parts", json::array({json{{"inline_data", {{"mime_type", "image/png"}, {"data", "AAAA"}}}}})}}});
    CHECK_EQ(tapto::pruneHistoryImages(gemini, 0), std::size_t(1));
    CHECK(gemini[0]["parts"][0].contains("text"));
    CHECK(!gemini[0]["parts"][0].contains("inline_data"));
}

// --- tool display hook ------------------------------------------------------

void test_tool_display_name() {
    ToolSpec plain;
    plain.name = "plain";

    ToolSpec labelled;
    labelled.name = "edit";
    labelled.display = [](const json& in) { return "Edit " + in.value("path", std::string("?")); };

    ToolSpec broken;
    broken.name = "broken";
    broken.display = [](const json&) -> std::string { throw std::runtime_error("boom"); };

    std::vector<ToolSpec> tools{plain, labelled, broken};
    CHECK_EQ(getToolDisplayName(tools, "plain", json::object()), std::string("plain"));
    CHECK_EQ(getToolDisplayName(tools, "edit", json{{"path", "a.cpp"}}), std::string("Edit a.cpp"));
    CHECK_EQ(getToolDisplayName(tools, "broken", json::object()), std::string("broken"));
    CHECK_EQ(getToolDisplayName(tools, "unknown", json::object()), std::string("unknown"));
}

void test_tool_definition_formats() {
    ToolSpec spec;
    spec.name = "t";
    spec.description = "d";
    spec.parameters = json{{"type", "object"}};

    CHECK(tool_definition_to_json(spec, ToolFormat::Claude).contains("input_schema"));
    CHECK(tool_definition_to_json(spec, ToolFormat::OpenAI).contains("parameters"));
    CHECK(tool_definition_to_json(spec, ToolFormat::Gemini).contains("parameters"));

    spec.claude_builtin_type = "text_editor_20250728";
    const json builtin = tool_definition_to_json(spec, ToolFormat::Claude);
    CHECK_EQ(builtin.value("type", std::string()), std::string("text_editor_20250728"));
    CHECK(!builtin.contains("input_schema"));
    // Other dialects still get the explicit schema.
    CHECK(tool_definition_to_json(spec, ToolFormat::OpenAI).contains("parameters"));
}

} // namespace

int main() {
    test_config_roundtrip();
    test_secret_literal_and_env();
    test_sanitize_utf8();
    test_base64();
    test_tool_image_context();
    test_prune_history_images();
    test_tool_display_name();
    test_tool_definition_formats();

    if (g_failures) {
        std::cerr << g_failures << " check(s) failed\n";
        return 1;
    }
    std::cout << "libtapto: all checks passed\n";
    return 0;
}

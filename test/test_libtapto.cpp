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
#include "tapto/fstools.h"
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

// --- folders ----------------------------------------------------------------

struct Tree {
    fs::path root;
    explicit Tree(const char* name) : root(scratch_file(name)) {
        fs::remove_all(root);
        fs::create_directories(root / "proj" / "src");
        fs::create_directories(root / "proj" / "build");
        fs::create_directories(root / "proj" / ".git");
        fs::create_directories(root / "other");
        write(root / "proj" / "README.md", "# proj\n\nHello world.\n");
        write(root / "proj" / "src" / "main.cpp", "int main() {\n  return 0; // needle\n}\n");
        write(root / "proj" / "src" / "blob.bin", std::string("PNG\0\0\0junk", 10));
        write(root / "proj" / "build" / "out.o", "needle in build output\n");
        write(root / "other" / "secret.txt", "not for the model\n");
    }
    ~Tree() { std::error_code ec; fs::remove_all(root, ec); }
    static void write(const fs::path& p, const std::string& content) {
        std::ofstream out(p, std::ios::binary);
        out << content;
    }
};

std::string run(const std::vector<ToolSpec>& tools, const char* name, json in) {
    Context ctx;
    for (const auto& t : tools)
        if (t.name == name) return t.executor(ctx, in);
    return "no such tool";
}

bool starts_with(const std::string& s, const char* prefix) { return s.rfind(prefix, 0) == 0; }
bool contains(const std::string& s, const char* needle) { return s.find(needle) != std::string::npos; }

void test_folder_set_grants() {
    Tree t("folders-grant");
    tapto::FolderSet set;
    CHECK(set.empty());

    std::string label;
    CHECK_EQ(set.add((t.root / "proj").string(), &label), std::string(""));
    CHECK_EQ(label, std::string("proj"));
    CHECK_EQ(set.folders().size(), std::size_t(1));

    // Granting again, or a subfolder, adds nothing and names the cover.
    CHECK_EQ(set.add((t.root / "proj" / "src").string(), &label), std::string(""));
    CHECK_EQ(label, std::string("proj"));
    CHECK_EQ(set.folders().size(), std::size_t(1));

    // Bad grants are refused with a reason.
    CHECK(starts_with(set.add((t.root / "nope").string()), "ERROR:"));
    CHECK(starts_with(set.add((t.root / "proj" / "README.md").string()), "ERROR:"));
    CHECK(starts_with(set.add(""), "ERROR:"));

    // A second folder with the same last component gets a distinct label.
    fs::create_directories(t.root / "other" / "proj");
    CHECK_EQ(set.add((t.root / "other" / "proj").string(), &label), std::string(""));
    CHECK_EQ(label, std::string("proj-2"));

    // Remove by label and by path.
    CHECK(set.remove("proj-2"));
    CHECK(!set.remove("proj-2"));
    CHECK(set.remove((t.root / "proj").string()));
    CHECK(set.empty());
}

void test_folder_set_resolve() {
    Tree t("folders-resolve");
    tapto::FolderSet set;
    fs::path out;
    std::string err;

    // Nothing granted: every path is refused, and the message says how to fix it.
    CHECK(!set.resolve("anything", out, err));
    CHECK(contains(err, "/add-folder"));

    set.add((t.root / "proj").string());

    // Label-relative, bare label, absolute, and root-relative (one folder).
    CHECK(set.resolve("proj/src/main.cpp", out, err));
    CHECK(fs::equivalent(out, t.root / "proj" / "src" / "main.cpp"));
    CHECK(set.resolve("proj", out, err));
    CHECK(fs::equivalent(out, t.root / "proj"));
    CHECK(set.resolve((t.root / "proj" / "README.md").string(), out, err));
    CHECK(set.resolve("src/main.cpp", out, err));
    CHECK(fs::equivalent(out, t.root / "proj" / "src" / "main.cpp"));

    // Escapes: dot-dot, an absolute path elsewhere, a sibling folder.
    CHECK(!set.resolve("proj/../other/secret.txt", out, err));
    CHECK(contains(err, "outside"));
    CHECK(!set.resolve((t.root / "other" / "secret.txt").string(), out, err));
    CHECK(!set.resolve("proj/src/../../other/secret.txt", out, err));

    // A prefix that merely starts with the root's name is not inside it.
    fs::create_directories(t.root / "project-evil");
    CHECK(!set.resolve((t.root / "project-evil").string(), out, err));

    // display() gives the model-facing form back.
    CHECK_EQ(set.display(t.root / "proj" / "src" / "main.cpp"), std::string("proj/src/main.cpp"));
    CHECK_EQ(set.display(t.root / "proj"), std::string("proj"));

    // With two folders a bare relative path is ambiguous and says so.
    set.add((t.root / "other").string());
    CHECK(!set.resolve("src/main.cpp", out, err));
    CHECK(contains(err, "ambiguous"));
    CHECK(set.resolve("other/secret.txt", out, err));
}

void test_folder_tools() {
    Tree t("folders-tools");
    tapto::FolderSet set;
    auto tools = tapto::folder_tools(set);
    CHECK_EQ(tools.size(), std::size_t(4));

    // Before any grant every tool explains itself rather than failing oddly.
    CHECK(contains(run(tools, "list_folders", json::object()), "No folders"));
    CHECK(starts_with(run(tools, "read_file", json{{"path", "x"}}), "ERROR:"));

    set.add((t.root / "proj").string());
    CHECK(contains(run(tools, "list_folders", json::object()), "proj"));

    // list_files skips build/ and .git/, shows sizes, honours the glob.
    const std::string listing = run(tools, "list_files", json::object());
    CHECK(contains(listing, "proj/README.md"));
    CHECK(contains(listing, "proj/src/main.cpp"));
    CHECK(!contains(listing, "out.o"));
    CHECK(contains(listing, "bytes"));
    const std::string cpp_only = run(tools, "list_files", json{{"pattern", "*.cpp"}});
    CHECK(contains(cpp_only, "main.cpp"));
    CHECK(!contains(cpp_only, "README"));
    CHECK(contains(run(tools, "list_files", json{{"pattern", "*.zzz"}}), "No files"));

    // read_file: numbered lines, slices, binary detection, directory refusal.
    const std::string whole = run(tools, "read_file", json{{"path", "proj/src/main.cpp"}});
    CHECK(contains(whole, "1|int main() {"));
    CHECK(contains(whole, "3|}"));
    CHECK(contains(whole, "(3 lines)"));
    const std::string slice = run(tools, "read_file", json{{"path", "proj/src/main.cpp"}, {"start_line", 2}, {"end_line", 2}});
    CHECK(contains(slice, "2|  return 0;"));
    CHECK(!contains(slice, "1|int"));
    CHECK(contains(slice, "showing 2-2"));
    CHECK(contains(run(tools, "read_file", json{{"path", "proj/src/blob.bin"}}), "binary"));
    CHECK(starts_with(run(tools, "read_file", json{{"path", "proj/src"}}), "ERROR:"));
    CHECK(starts_with(run(tools, "read_file", json{{"path", "proj/nope.txt"}}), "ERROR:"));
    CHECK(starts_with(run(tools, "read_file", json{{"path", "proj/../other/secret.txt"}}), "ERROR:"));
    CHECK(starts_with(run(tools, "read_file", json{{"path", "proj/src/main.cpp"}, {"start_line", 9}}), "ERROR:"));

    // search_files: finds the needle in src, not in build; binary skipped.
    const std::string found = run(tools, "search_files", json{{"query", "needle"}});
    CHECK(contains(found, "proj/src/main.cpp"));
    CHECK(contains(found, "2: "));
    CHECK(!contains(found, "out.o"));
    CHECK(contains(run(tools, "search_files", json{{"query", "absent-string"}}), "No files"));
    CHECK(starts_with(run(tools, "search_files", json{{"query", ""}}), "ERROR:"));

    // The prompt paragraph names the folder; empty when nothing is granted.
    CHECK(contains(tapto::folder_prompt(set), "proj"));
    set.clear();
    CHECK(tapto::folder_prompt(set).empty());
    // Tools built earlier see the cleared set.
    CHECK(contains(run(tools, "list_folders", json::object()), "No folders"));
}

void test_fs_helpers() {
    CHECK(tapto::wildcard_match("*.cpp", "main.cpp"));
    CHECK(!tapto::wildcard_match("*.cpp", "main.h"));
    CHECK(tapto::wildcard_match("ma?n.*", "main.cpp"));
    CHECK(tapto::wildcard_match("*", ""));
    CHECK(tapto::is_noise_dir(".git"));
    CHECK(tapto::is_noise_dir("build-ide"));
    CHECK(!tapto::is_noise_dir("builder"));
    CHECK_EQ(tapto::content_lines("a\nb\n").size(), std::size_t(2));
    CHECK_EQ(tapto::content_lines("a\r\nb").size(), std::size_t(2));
    CHECK_EQ(tapto::content_lines("").size(), std::size_t(0));
    CHECK(tapto::looks_binary(std::string("ab\0cd", 5)));
    CHECK(!tapto::looks_binary("plain"));
    CHECK(contains(tapto::cap_output(std::string(100, 'x'), 10), "truncated"));
    CHECK_EQ(tapto::cap_output("short", 10), std::string("short"));
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
    test_fs_helpers();
    test_folder_set_grants();
    test_folder_set_resolve();
    test_folder_tools();

    if (g_failures) {
        std::cerr << g_failures << " check(s) failed\n";
        return 1;
    }
    std::cout << "libtapto: all checks passed\n";
    return 0;
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#include "tapto/editor.h"

#include "tapto/context.h"
#include "tapto/program.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace tapto {

namespace {

// --- line endings ---------------------------------------------------------
//
// Files are read and written byte-exact, and `view` renders each line with its
// CR stripped. The model therefore composes edits in LF terms while a file
// checked out on Windows holds CRLF, so an edit has to treat a line ending as a
// line ending rather than as two particular bytes — otherwise every multi-line
// str_replace on such a file fails to match.
//
// Files with a long Windows history can be mixed, which is why matching is a
// per-character scan rather than normalise-then-compare: every byte outside the
// edited span keeps whatever ending it already had.

// Length of the line ending at s[i], or 0 if there isn't one there. A lone CR
// is deliberately not an ending: in a file that is otherwise LF or CRLF it is
// far more likely to be data than a line break.
size_t eol_len(const std::string& s, size_t i) {
    if (i >= s.size()) return 0;
    if (s[i] == '\r' && i + 1 < s.size() && s[i + 1] == '\n') return 2;
    if (s[i] == '\n') return 1;
    return 0;
}

// Match `needle` against `content` starting at `at`, with any line ending
// matching any other. Returns the end offset of the match (which may differ
// from at + needle.size(), since the endings can be of different lengths), or
// npos if it doesn't match here.
size_t match_at(const std::string& content, const std::string& needle, size_t at) {
    size_t i = at, j = 0;
    while (j < needle.size()) {
        if (const size_t n = eol_len(needle, j)) {
            const size_t c = eol_len(content, i);
            if (c == 0) return std::string::npos;
            i += c;
            j += n;
        } else {
            if (i >= content.size() || content[i] != needle[j]) return std::string::npos;
            ++i;
            ++j;
        }
    }
    return i;
}

// Every non-overlapping match of `needle`, comparing line endings loosely.
std::vector<std::pair<size_t, size_t>> find_all_loose(const std::string& content,
                                                      const std::string& needle) {
    std::vector<std::pair<size_t, size_t>> hits;
    if (needle.empty()) return hits;
    for (size_t i = 0; i < content.size();) {
        const size_t end = match_at(content, needle, i);
        if (end == std::string::npos) {
            ++i;
        } else {
            hits.push_back({i, end});
            i = (end > i) ? end : i + 1;
        }
    }
    return hits;
}

// The ending style a stretch of text uses. Text with no ending in it at all
// inherits `fallback`, which is how a single-line replacement in a CRLF file
// still gets CRLF when it turns into several lines.
std::string eol_style(const std::string& s, const std::string& fallback) {
    size_t crlf = 0, lf = 0;
    for (size_t i = 0; i < s.size();) {
        const size_t n = eol_len(s, i);
        if (n == 2) { ++crlf; i += 2; }
        else if (n == 1) { ++lf; ++i; }
        else ++i;
    }
    if (crlf == 0 && lf == 0) return fallback;
    return crlf >= lf ? "\r\n" : "\n";
}

// Rewrite every line ending in `text` as `eol`.
std::string with_eol(const std::string& text, const std::string& eol) {
    std::string out;
    out.reserve(text.size() + text.size() / 16);
    for (size_t i = 0; i < text.size();) {
        if (const size_t n = eol_len(text, i)) {
            out += eol;
            i += n;
        } else {
            out += text[i++];
        }
    }
    return out;
}

// Byte offset where line `line` starts (0-based, counting line endings). Past
// the last line this is the end of the content, so inserting there appends.
size_t line_start_offset(const std::string& s, int line) {
    size_t off = 0;
    int seen = 0;
    while (seen < line && off < s.size()) {
        if (const size_t n = eol_len(s, off)) {
            off += n;
            ++seen;
        } else {
            ++off;
        }
    }
    return off;
}

bool write_file(const fs::path& path, const std::string& content) {
    std::error_code ec;
    if (path.has_parent_path()) fs::create_directories(path.parent_path(), ec);
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out << content;
    return out.good();
}

// The text of `path`, from the document that holds it when there is one, else
// from the file. False when it cannot be had: `error` says why when a document
// refused, and is empty when the file is missing or unreadable, for the caller
// to say which.
bool load(Buffers* buffers, const fs::path& path, std::string& content, std::string& error) {
    error.clear();
    if (buffers) {
        switch (buffers->read(path, content, error)) {
            case Buffers::Result::Done: return true;
            case Buffers::Result::Failed:
                if (error.empty()) error = "the open document could not be read";
                return false;
            case Buffers::Result::NotOpen: error.clear(); break;
        }
    }
    return read_file(path, content);
}

// Write `content` to the document that holds `path`, or else to the file.
// The returned error is empty on success.
std::string store(Buffers* buffers, const fs::path& path, const std::string& content) {
    std::string error;
    if (buffers) {
        switch (buffers->write(path, content, error)) {
            case Buffers::Result::Done: return {};
            case Buffers::Result::Failed:
                return "ERROR: Failed to write " + path.string() + ": " +
                       (error.empty() ? std::string("the open document refused the edit") : error);
            case Buffers::Result::NotOpen: break;
        }
    }
    if (!write_file(path, content)) return "ERROR: Failed to write " + path.string();
    return {};
}

// --- text editor tool -----------------------------------------------------

std::string execute_text_editor(const PathRules& rules, Buffers* buffers, const json& in) {
    try {
        if (!in.contains("command")) return "ERROR: 'command' not present.";
        std::string command = in["command"];

        // file_text is the content field for create/write only. The two genuinely
        // misleading cases are str_replace and insert, where a stray file_text
        // would otherwise be silently ignored (str_replace would delete old_str
        // instead of writing the intended text). Fail loudly there, naming the
        // field to use, so the model self-corrects on the first retry.
        //
        // view and delete simply ignore file_text: it is irrelevant to them, and
        // rejecting it only trips the model up — it habitually emits
        // file_text: "" on view calls, sees the error, doesn't realise it's the
        // field it's adding, and loops (see tapto.log, the config.c session).
        if (in.contains("file_text") &&
            (command == "str_replace" || command == "insert")) {
            return "ERROR: 'file_text' is only for the 'create' and 'write' commands. "
                   "For str_replace or insert, pass the text as 'new_str' "
                   "(insert also takes 'insert_line').";
        }

        if (command == "view") {
            if (!in.contains("path")) return "ERROR: 'path' not present.";
            fs::path path;
            {
                std::string sandbox_err;
                // A read: the read scope (the working directory and every
                // granted folder, whatever their mode, so .git and read-only
                // grants stay readable), and the program's own folders.
                if (!rules.resolve_for_read(in["path"].get<std::string>(), path, sandbox_err)) {
                    return sandbox_err;
                }
            }
            // An open document is shown as it is in the editor, whether or
            // not it has been saved, or even exists on disk yet.
            std::string content, error;
            const Buffers::Result held =
                buffers ? buffers->read(path, content, error) : Buffers::Result::NotOpen;
            if (held == Buffers::Result::Failed) {
                return "ERROR: Failed to read " + path.string() + ": " +
                       (error.empty() ? std::string("the open document could not be read") : error);
            }
            if (held == Buffers::Result::NotOpen) {
                std::error_code ec;
                if (!fs::exists(path, ec)) return "ERROR: File not found: " + path.string();

                if (fs::is_directory(path, ec)) {
                    std::vector<std::string> entries;
                    for (const auto& e : fs::directory_iterator(path, ec)) {
                        std::string name = e.path().filename().string();
                        if (e.is_directory(ec)) name += "/";
                        entries.push_back(name);
                    }
                    std::sort(entries.begin(), entries.end());
                    std::ostringstream out;
                    for (const auto& name : entries) out << name << "\n";
                    return out.str();
                }

                if (!read_file(path, content)) return "ERROR: Failed to read " + path.string();
            }
            // Numbering a binary file would put NULs and invalid UTF-8 into the
            // model's context and the chat transcript, which the UTF-8
            // sanitizer downstream cannot catch — they are valid UTF-8. cat,
            // head and tail refuse the same way, so `view` must not be the way
            // around them.
            if (looks_binary(content)) {
                return "ERROR: " + path.string() + " is a binary file (" +
                       std::to_string(content.size()) + " bytes); it has no text to show.";
            }
            // content_lines, not split_lines: a trailing newline must not show
            // up as an extra empty numbered line, or `view` and `wc -l` disagree
            // about how long the file is and the model mis-aims its view_range.
            auto lines = content_lines(content);
            if (lines.empty()) return "(empty file)";

            int start = 1;
            int end = static_cast<int>(lines.size());
            if (in.contains("view_range")) {
                json range = in["view_range"];
                if (range.is_string()) {
                    try { range = json::parse(range.get<std::string>()); }
                    catch (const std::exception& e) {
                        return std::string("ERROR: 'view_range' could not be parsed: ") + e.what();
                    }
                }
                if (!range.is_array() || range.size() != 2 ||
                    !range[0].is_number_integer() || !range[1].is_number_integer()) {
                    return "ERROR: 'view_range' must be an array of two integers, e.g. [1, 50]";
                }
                start = range[0];
                end = range[1] < 0 ? static_cast<int>(lines.size()) : range[1].get<int>();
                if (start < 1 || end > static_cast<int>(lines.size()) || start > end) {
                    return "ERROR: Invalid line range [" + std::to_string(start) + ", " +
                           std::to_string(end) + "]; the file has " +
                           std::to_string(lines.size()) + " lines (use -1 as the end for the last line)";
                }
            }

            // Cap the rendered output so a single huge file can't blow the
            // context window / cost (in line with find_files and run_command).
            constexpr size_t kMaxViewBytes = 64000;
            std::ostringstream out;
            size_t emitted = 0;
            bool truncated = false;
            for (int i = start - 1; i < end && i < static_cast<int>(lines.size()); ++i) {
                std::string row = std::to_string(i + 1) + "|" + lines[i] + "\n";
                if (emitted + row.size() > kMaxViewBytes) {
                    truncated = true;
                    break;
                }
                out << row;
                emitted += row.size();
            }
            std::string result = out.str();
            if (truncated) {
                result += "... [truncated at " + std::to_string(kMaxViewBytes) +
                          " bytes; use view_range to see more]\n";
            }
            return result;
        }

        if (command == "create") {
            if (!in.contains("path")) return "ERROR: 'path' not present.";
            if (!in.contains("file_text")) return "ERROR: 'file_text' required for create command.";
            fs::path path;
            {
                std::string sandbox_err;
                if (!rules.resolve_for_editor(in["path"].get<std::string>(), path, sandbox_err)) {
                    return sandbox_err;
                }
            }
            std::error_code ec;
            if (fs::exists(path, ec)) {
                return "ERROR: File already exists: " + path.string() +
                       ". Use str_replace to edit part of it, or the 'write' command "
                       "to replace the whole file.";
            }
            if (!write_file(path, in["file_text"].get<std::string>())) {
                return "ERROR: Failed to write " + path.string();
            }
            return "OK";
        }

        if (command == "write") {
            // Full overwrite, for the "rewrite this whole file" intent that
            // str_replace (needs a unique old_str) and create (refuses existing
            // files) can't express. file_text is the entire new content.
            if (!in.contains("path")) return "ERROR: 'path' not present.";
            if (!in.contains("file_text"))
                return "ERROR: 'file_text' required for the write command.";
            const std::string input = in["path"].get<std::string>();
            fs::path path;
            {
                std::string sandbox_err;
                if (!rules.resolve_for_editor(input, path, sandbox_err)) {
                    return sandbox_err;
                }
            }
            // The mirror of create's "already exists": write is for a file
            // that is there. Letting it create one would turn a mistyped path
            // into a quiet new file beside the one the model meant to rewrite.
            std::error_code ec;
            if (!fs::exists(path, ec)) {
                return "ERROR: Not found: " + path.string() +
                       ". write replaces an existing file; use 'create' for a new one.";
            }
            if (fs::is_directory(path, ec)) {
                return "ERROR: '" + path.string() + "' is a directory.";
            }
            if (const std::string err = store(buffers, path, in["file_text"].get<std::string>());
                !err.empty()) {
                return err;
            }
            // Echo the path as the model gave it, as the other commands' errors
            // do not: the resolved one is absolute and machine-specific.
            return "OK: wrote " + input;
        }

        if (command == "delete") {
            // Remove a single file. The sandbox, the .git guard, and
            // read-only-grant refusal all come from the editor's resolver, so a
            // delete is exactly as reachable (and as protected) as a write.
            // Directories are refused: there is no recursive delete, so a
            // mis-targeted path can never take a tree (or a repo) with it.
            if (!in.contains("path")) return "ERROR: 'path' not present.";
            const std::string input = in["path"].get<std::string>();
            fs::path path;
            {
                std::string sandbox_err;
                if (!rules.resolve_for_editor(input, path, sandbox_err)) {
                    return sandbox_err;
                }
            }
            std::error_code ec;
            if (!fs::exists(path, ec))
                return "ERROR: Not found: " + path.string() + " (nothing to delete).";
            if (fs::is_directory(path, ec))
                return "ERROR: '" + path.string() + "' is a directory. "
                       "delete removes a single file only; there is no recursive delete. "
                       "Delete the files inside it one at a time instead.";
            if (!fs::remove(path, ec))
                return "ERROR: Failed to delete " + path.string() +
                       (ec ? (": " + ec.message()) : std::string());
            return "OK: deleted " + input;
        }

        if (command == "str_replace") {
            if (!in.contains("path")) return "ERROR: 'path' not present.";
            if (!in.contains("old_str")) {
                return "ERROR: str_replace requires 'old_str'. To delete the matched text, pass new_str=\"\".";
            }
            // To delete matched text the model must say so with an explicit
            // new_str:"" — a missing new_str is how a whole-file write sent as
            // file_text used to silently become a deletion of old_str.
            if (!in.contains("new_str")) {
                return "ERROR: str_replace requires 'new_str' (the replacement text). "
                       "Pass new_str=\"\" to delete the matched text. If you meant to "
                       "write a whole file, use the 'write' command with 'file_text'.";
            }
            fs::path path;
            {
                std::string sandbox_err;
                if (!rules.resolve_for_editor(in["path"].get<std::string>(), path, sandbox_err)) {
                    return sandbox_err;
                }
            }
            std::string content, error;
            if (!load(buffers, path, content, error)) {
                if (!error.empty()) return "ERROR: Failed to read " + path.string() + ": " + error;
                return "ERROR: File not found: " + path.string() + ". Use the create command to create it.";
            }
            std::string old_str = in["old_str"].get<std::string>();
            std::string new_str = in.value("new_str", "");
            if (old_str.empty()) {
                return "ERROR: old_str cannot be empty. Use 'insert' to add new content.";
            }

            // Matching compares line endings as line endings throughout, not
            // just as a fallback when the byte-exact search misses. old_str is
            // composed from `view` output, which strips CR, so on a Windows file
            // a byte-exact search would miss every multi-line old_str — and,
            // just as important, two places that differ only in their endings
            // are indistinguishable to the model that asked for "the unique
            // occurrence", so both have to count towards ambiguity.
            const auto hits = find_all_loose(content, old_str);
            if (hits.empty()) return "ERROR: String not found: " + old_str;
            if (hits.size() > 1) {
                return "ERROR: Multiple occurrences found (" + std::to_string(hits.size()) +
                       "). Please provide a unique string.";
            }
            const size_t begin = hits[0].first;
            const size_t end = hits[0].second;

            // Write the replacement in whatever ending the text it replaces
            // used, so an edit inside a CRLF file — or inside the CRLF half of a
            // mixed one — doesn't leave an LF line behind it.
            const std::string style =
                eol_style(content.substr(begin, end - begin), eol_style(content, "\n"));
            content.replace(begin, end - begin, with_eol(new_str, style));
            if (const std::string err = store(buffers, path, content); !err.empty()) return err;
            return "OK";
        }

        if (command == "insert") {
            if (!in.contains("path")) return "ERROR: 'path' not present.";
            if (!in.contains("insert_line") || !in.contains("new_str")) {
                return "ERROR: insert_line and new_str required.";
            }
            fs::path path;
            {
                std::string sandbox_err;
                if (!rules.resolve_for_editor(in["path"].get<std::string>(), path, sandbox_err)) {
                    return sandbox_err;
                }
            }
            std::string content, error;
            if (!load(buffers, path, content, error)) {
                return "ERROR: Failed to read " + path.string() + (error.empty() ? "" : ": " + error);
            }

            int insert_line = in["insert_line"];
            std::string new_str = in["new_str"].get<std::string>();
            auto lines = split_lines(content);
            if (insert_line < 0 || insert_line > static_cast<int>(lines.size())) {
                return "ERROR: Invalid insert_line";
            }

            // Splice at a byte offset rather than rebuilding the file from split
            // lines: rebuilding rejoins with one ending and so rewrites every
            // line in the file, which turns a one-line insert into a whole-file
            // diff and normalises a mixed file.
            const std::string eol = eol_style(content, "\n");
            const size_t offset = line_start_offset(content, insert_line);
            const std::string piece = with_eol(new_str, eol);
            if (offset == content.size() && !content.empty() && content.back() != '\n') {
                // Appending to a file that doesn't end in a newline: start a new
                // line for the insert, and leave the file without one as before.
                content += eol + piece;
            } else {
                content.insert(offset, piece + eol);
            }
            if (const std::string err = store(buffers, path, content); !err.empty()) return err;
            return "Insertion successful at line " + std::to_string(insert_line);
        }

        return "ERROR: Unknown command: " + command;
    } catch (const std::exception& e) {
        return std::string("ERROR: text editor failed: ") + e.what();
    }
}

// --- file search tool -----------------------------------------------------
// Content search goes through find_matching_lines (tapto/fstools.h), which
// streams the file so it can reach files far larger than the context window.

std::string execute_find_files(const PathRules& rules, const json& in) {
    try {
        if (!in.contains("filename")) return "ERROR: 'filename' not present.";
        std::string pattern = in["filename"].get<std::string>();
        std::string start = in.value("path", std::string("."));

        std::string query;
        bool has_query = in.contains("search_string") &&
                         in["search_string"].is_string() &&
                         !in["search_string"].get<std::string>().empty();
        if (has_query) query = in["search_string"].get<std::string>();

        fs::path base;
        {
            std::string sandbox_err;
            if (!rules.resolve(start, base, sandbox_err)) return sandbox_err;
        }
        std::error_code ec;
        if (!fs::exists(base, ec)) return "ERROR: Path not found: " + start;

        constexpr size_t kMaxFiles = 100;
        constexpr size_t kMaxLinesPerFile = 20;

        struct Match {
            std::string path;
            std::vector<std::pair<int, std::string>> lines;
        };
        std::vector<Match> results;

        fs::recursive_directory_iterator it(base, fs::directory_options::skip_permission_denied, ec), end;
        for (; it != end && results.size() < kMaxFiles; it.increment(ec)) {
            if (ec) break;
            const fs::path& p = it->path();
            // Never follow symlinks — they could point outside the sandbox.
            // (Recursive iteration does not descend into directory symlinks by
            // default; this also skips symlinked files for content grep.)
            if (it->is_symlink(ec)) continue;
            if (it->is_directory(ec)) {
                if (is_noise_dir(p.filename().string())) it.disable_recursion_pending();
                continue;
            }
            if (!it->is_regular_file(ec)) continue;
            if (!wildcard_match(pattern, p.filename().string())) continue;

            Match m;
            // Report paths relative to the sandbox root so they match how the
            // model supplies paths and round-trip back into the other tools.
            // (The iterator yields absolute paths because `base` is absolute.)
            // A hit inside a writable granted folder is shown as
            // "<label>/<rest>", which the editor accepts back.
            m.path = rules.display(p);
            if (m.path.empty()) m.path = p.generic_string();

            if (has_query) {
                // Stream the file line-by-line (find_matching_lines) rather than
                // loading it whole: a content search must reach files far larger
                // than the context window (the old 5 MiB cap made find_files
                // report "no files" on any big log). The probe inside bails out
                // on binaries, and we keep at most kMaxLinesPerFile hits per file.
                auto lines = find_matching_lines(p, query, kMaxLinesPerFile);
                if (lines.empty()) continue;   // file name matched, content didn't
                for (const auto& lm : lines) m.lines.emplace_back(lm.line, std::move(lm.text));
            }

            results.push_back(std::move(m));
        }

        if (results.empty()) {
            if (has_query) {
                return "No files matching '" + pattern + "' containing '" + query + "'";
            }
            return "No files matching '" + pattern + "'";
        }

        std::ostringstream out;
        out << "Found " << results.size() << " file(s):\n\n";
        for (const auto& m : results) {
            out << m.path << "\n";
            for (const auto& line : m.lines) {
                out << "  " << line.first << ": " << line.second << "\n";
            }
            if (!m.lines.empty()) out << "\n";
        }
        return out.str();
    } catch (const std::exception& e) {
        return std::string("ERROR: find_files failed: ") + e.what();
    }
}

// --- status-line labels ------------------------------------------------------
//
// What the terminal shows while a tool runs: "Edit src/foo.cpp" rather than
// the tool name and a JSON blob. Attached to each ToolSpec as its `display`
// hook; the backends call it through getToolDisplayName() and fall back to the
// raw name if it throws or is unset.
//
// str_replace_based_edit_tool:
//   view (file, range)        -> "View src/foo.cpp:10-50"
//   view (file)               -> "View src/foo.cpp"
//   create                    -> "Create src/foo.cpp"
//   write                     -> "Write src/foo.cpp"
//   delete                    -> "Delete src/foo.cpp"
//   str_replace               -> "Edit src/foo.cpp"
//   insert                    -> "Insert src/foo.cpp"
//   unknown sub-command       -> the path
//
// find_files:
//   with search_string        -> "Search *.cpp ~\"query\""
//   without                   -> "Find *.cpp"

std::string display_text_editor(const json& input) {
    if (!input.is_object()) return "str_replace_based_edit_tool";
    std::string cmd  = input.contains("command") && input["command"].is_string()
                       ? input["command"].get<std::string>() : "";
    std::string path = input.contains("path") && input["path"].is_string()
                       ? input["path"].get<std::string>() : "";

    if (cmd == "view") {
        std::string label = "View " + path;
        // view_range: show line numbers when present
        if (input.contains("view_range")) {
            const auto& vr = input["view_range"];
            // Accept both a JSON array and a string-encoded array.
            auto try_range = [&](const json& r) -> std::string {
                if (r.is_array() && r.size() == 2 &&
                    r[0].is_number_integer() && r[1].is_number_integer()) {
                    int end = r[1].get<int>();
                    return ":" + std::to_string(r[0].get<int>()) +
                           "-" + (end < 0 ? "EOF" : std::to_string(end));
                }
                return "";
            };
            if (vr.is_string()) {
                try {
                    label += try_range(json::parse(vr.get<std::string>()));
                } catch (...) {}
            } else {
                label += try_range(vr);
            }
        }
        return label;
    }
    if (cmd == "create")      return "Create " + path;
    if (cmd == "write")       return "Write "  + path;
    if (cmd == "delete")      return "Delete " + path;
    if (cmd == "str_replace") return "Edit "   + path;
    if (cmd == "insert")      return "Insert " + path;
    // Unknown sub-command: fall back to path only.
    return path.empty() ? "str_replace_based_edit_tool" : path;
}

std::string display_find_files(const json& input) {
    if (!input.is_object()) return "find_files";
    std::string pattern = input.contains("filename") && input["filename"].is_string()
                          ? input["filename"].get<std::string>() : "*";
    bool has_query = input.contains("search_string") &&
                     input["search_string"].is_string() &&
                     !input["search_string"].get<std::string>().empty();
    if (has_query)
        return "Search " + pattern + " ~\"" + input["search_string"].get<std::string>() + "\"";
    return "Find " + pattern;
}

} // namespace

std::vector<ToolSpec> editor_tools(const FolderSet& folders, std::shared_ptr<Buffers> buffers) {
    std::vector<ToolSpec> tools;
    const PathRules rules(folders);

    // Where the editor reaches, as the model is told it: the working
    // directory when the program has one, the granted folders, and the
    // program's own '@' folders.
    const std::string reach =
        std::string(folders.home() ? "Relative paths are in the working directory. Beyond "
                                     "it, this tool reaches "
                                   : "This tool reaches ") +
        "the folders the user granted and " + program_name() +
        "'s own folders, named with an '@' label: @tmp (long tool output, read-only) and a "
        "plugin's folder, @<plugin>, when it has one. Address a file in one as "
        "<label>/<path>, e.g. @tmp/<file>.";

    // str_replace text editor. Declared as Claude's built-in for Anthropic,
    // and with an explicit schema for OpenAI/Gemini.
    ToolSpec editor;
    editor.name = "str_replace_based_edit_tool";
    editor.description =
        "View, create, and edit files on the local filesystem. Commands:\n"
        "- view: show a file (with line numbers) or list a directory. Optional view_range [start,end].\n"
        "- create: create a new file with file_text (fails if it already exists).\n"
        "- write: overwrite an entire existing file with file_text (use for full rewrites).\n"
        "- delete: remove a single file (directories are not deleted).\n"
        "- str_replace: replace the unique occurrence of old_str with new_str.\n"
        "- insert: insert new_str after line insert_line (0 = beginning).\n"
        "file_text is the content field for create and write only; str_replace and "
        "insert take their text in new_str.\n"
        + reach;
    editor.claude_builtin_type = "text_editor_20250728";
    editor.parameters = {
        {"type", "object"},
        {"properties", {
            {"command", {
                {"type", "string"},
                {"enum", {"view", "create", "write", "delete", "str_replace", "insert"}},
                {"description", "The edit command to run."}
            }},
            {"path", {{"type", "string"}, {"description", "File or directory path."}}},
            {"file_text", {{"type", "string"},
                           {"description", "Full content for the create and write commands. "
                                           "NOT used by str_replace or insert."}}},
            {"old_str", {{"type", "string"}, {"description", "Text to replace (str_replace); must be unique."}}},
            {"new_str", {{"type", "string"},
                         {"description", "Replacement text (str_replace) or inserted text (insert). "
                                          "Required for both; pass an empty string to delete in str_replace."}}},
            {"insert_line", {{"type", "integer"}, {"description", "Line number to insert after (insert)."}}},
            {"view_range", {
                {"type", "array"},
                {"items", {{"type", "integer"}}},
                {"description", "Optional [start, end] line range for view (1-based; end -1 = EOF)."}
            }},
        }},
        {"required", {"command", "path"}},
    };
    editor.executor = [rules, buffers](Context&, const json& in) {
        return execute_text_editor(rules, buffers.get(), in);
    };
    editor.display = display_text_editor;
    tools.push_back(std::move(editor));

    // File search (find + optional content grep).
    ToolSpec find;
    find.name = "find_files";
    find.description =
        "Find files under a directory by filename pattern, optionally grepping their contents. "
        "Supports wildcards: * (any sequence) and ? (single character).";
    find.parameters = {
        {"type", "object"},
        {"properties", {
            {"filename", {{"type", "string"}, {"description", "Filename pattern, e.g. '*.cpp', 'test?.txt'."}}},
            {"path", {{"type", "string"}, {"description", "Starting directory. Defaults to '.'."}}},
            {"search_string", {{"type", "string"}, {"description", "Optional text to search for inside matching files."}}},
        }},
        {"required", {"filename"}},
    };
    find.executor = [rules](Context&, const json& in) { return execute_find_files(rules, in); };
    find.display = display_find_files;
    tools.push_back(std::move(find));

    return tools;
}

} // namespace tapto

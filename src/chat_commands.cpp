// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#include "tapto/chat_commands.h"

#include "tapto/aibackend.h"
#include "tapto/aiconfig.h"
#include "tapto/config.h"
#include "tapto/context.h"
#include "tapto/fstools.h"
#include "tapto/log.h"
#include "tapto/paths.h"
#include "tapto/policy.h"
#include "tapto/program.h"
#include "tapto/provider.h"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <vector>

#include <nlohmann/json.hpp>

namespace tapto {

namespace {

std::string trim(const std::string& s) {
    const std::size_t b = s.find_first_not_of(" \t");
    if (b == std::string::npos) return "";
    const std::size_t e = s.find_last_not_of(" \t");
    return s.substr(b, e - b + 1);
}

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

// A path the user may have quoted, because it has spaces in it.
std::string unquote(const std::string& s) {
    const std::string t = trim(s);
    if (t.size() >= 2 && (t.front() == '"' || t.front() == '\'') && t.back() == t.front())
        return t.substr(1, t.size() - 2);
    return t;
}

// The words after "/<name>", when `line` is that command: "/cot" alone or
// followed by a blank, so "/cotton" is not /cot.
std::optional<std::string> args_of(const std::string& line, const char* name) {
    const std::string cmd = std::string("/") + name;
    if (line.rfind(cmd, 0) != 0) return std::nullopt;
    if (line.size() > cmd.size() && line[cmd.size()] != ' ' && line[cmd.size()] != '\t')
        return std::nullopt;
    return trim(line.substr(cmd.size()));
}

const char* level_phrase(Level level) {
    switch (level) {
    case Level::System: return "system config";
    case Level::Global: return "global config";
    case Level::Local: return "project config";
    case Level::Policy: return "your organization's policy";
    }
    return "config";
}

Level level_of(SettingScope scope) {
    return scope == SettingScope::Global ? Level::Global : Level::Local;
}

bool is_false(const std::string& v) {
    const std::string l = lower(trim(v));
    return l == "false" || l == "0" || l == "off" || l == "no";
}

ChatCommandResult ok(std::string text) { return {std::move(text), false}; }
ChatCommandResult fail(std::string text) { return {std::move(text), true}; }

// A scope a command may not take, or the program does not have.
std::optional<ChatCommandResult> refuse_scope(const ScopeFlags& f, const ChatCommands& c) {
    if (!f.error.empty()) return fail(f.error);
    if (f.scope == SettingScope::Project && !c.has_project)
        return fail(program_name() + " has no project config; use --global or --session.");
    return std::nullopt;
}

// --- /cot ----------------------------------------------------------------------

// The value print-cot has in the config now; on when no scope sets it.
bool configured_cot() {
    const auto v = get_effective("print-cot");
    return !(v && is_false(*v));
}

ChatCommandResult cot(const std::string& args, ChatCommands& c) {
    if (!c.ai) return fail("/cot is not available here.");
    const ScopeFlags f = parse_scope_flags(args);
    if (auto r = refuse_scope(f, c)) return *r;
    const std::string a = lower(f.rest);
    const SettingScope scope = f.scope.value_or(SettingScope::Global);
    auto state = [](bool on) { return std::string(on ? "on" : "off"); };

    if (a.empty()) {
        const std::string origin = setting_origin("print-cot");
        const bool session = c.ai->printCot() != configured_cot();
        return ok("CoT output: " + state(c.ai->printCot()) + " (" +
                  (session ? std::string("this session")
                           : origin.empty() ? std::string("the default") : origin) +
                  ")");
    }
    if (a == "unset") {
        if (scope != SettingScope::Session) {
            const SettingWrite w = write_setting("print-cot", std::nullopt, scope);
            if (!w.ok) return fail(w.text);
        }
        c.ai->setPrintCot(configured_cot());
        const std::string origin = setting_origin("print-cot");
        return ok("CoT output: " + state(c.ai->printCot()) + " (" +
                  (origin.empty() ? std::string("the default") : origin) + ")");
    }
    const bool on = a == "on" || a == "true" || a == "1" || a == "yes";
    const bool off = a == "off" || a == "false" || a == "0" || a == "no";
    if (!on && !off)
        return fail("usage: /cot [on|off|unset] [--session|--project|--global]   (/cot alone "
                    "shows it)");
    c.ai->setPrintCot(on);
    if (scope == SettingScope::Session) return ok("CoT output " + state(on) + " for this session.");
    const SettingWrite w = write_setting("print-cot", on ? "true" : "false", scope);
    if (!w.ok) return fail("CoT output " + state(on) + " for this session only: " + w.text);
    return ok("CoT output " + state(on) + " (" + w.text + ").");
}

// --- /effort -------------------------------------------------------------------

ChatCommandResult effort(const std::string& args, ChatCommands& c) {
    if (!c.ai || c.provider_name.empty()) return fail("/effort is not available here.");
    const ScopeFlags f = parse_scope_flags(args);
    if (auto r = refuse_scope(f, c)) return *r;
    const std::string key = c.provider_name + "-reasoning-effort";
    const std::string a = lower(f.rest);
    const SettingScope scope = f.scope.value_or(c.has_project ? SettingScope::Project
                                                              : SettingScope::Global);

    if (a.empty()) {
        const std::string& cur = c.ai->openaiReasoningEffort();
        if (cur.empty()) return ok(key + ": unset (the server picks its default)");
        const auto configured = get_effective(key);
        const std::string origin = setting_origin(key);
        return ok(key + " = " + cur + " (" +
                  (configured.value_or("") != cur ? std::string("this session") : origin) + ")");
    }
    // "unset", and the words people use for it.
    if (a == "unset" || a == "off" || a == "none" || a == "clear" || a == "reset" ||
        a == "default" || a == "auto" || a == "inherit" || a == "-") {
        if (scope == SettingScope::Session) {
            c.ai->setOpenaiReasoningEffort("");
            return ok(key + " cleared for this session (the server picks its default).");
        }
        const SettingWrite w = write_setting(key, std::nullopt, scope);
        if (!w.ok) return fail(w.text);
        c.ai->setOpenaiReasoningEffort(get_effective(key).value_or(""));
        const std::string& now = c.ai->openaiReasoningEffort();
        return ok(key + " removed from the " + level_phrase(level_of(scope)) + "; " +
                  (now.empty() ? std::string("unset now (the server picks its default).")
                               : "now " + now + " (" + setting_origin(key) + ")."));
    }
    // Only the openai dialect sends the field. Taking a value for another one
    // would look like it worked when it changed nothing.
    if (c.provider_dialect != "openai")
        return fail("/effort only applies to the openai dialect; '" + c.provider_name +
                    "' speaks " + c.provider_dialect + ".");
    // The value is passed through as it is: which words an endpoint accepts
    // is the endpoint's business.
    c.ai->setOpenaiReasoningEffort(a);
    if (scope == SettingScope::Session) return ok(key + " = " + a + " for this session.");
    const SettingWrite w = write_setting(key, a, scope);
    if (!w.ok) return fail(key + " = " + a + " for this session only: " + w.text);
    return ok(key + " = " + a + " (" + w.text + ").");
}

// --- /clear, /compact --------------------------------------------------------------

ChatCommandResult clear(ChatCommands& c) {
    if (!c.client) return fail("/clear is not available here.");
    if (!c.client->hasHistory()) return ok("(conversation cleared)");
    const std::string note = c.before_clear ? c.before_clear() : std::string();
    c.client->start();
    if (c.history_changed) c.history_changed();
    return ok("(conversation cleared" + note + ")");
}

// Ask the model to summarize the discussion so far, then restart from that
// summary; `focus` is what to keep in mind ("/compact the CMake changes").
ChatCommandResult compact(const std::string& focus, ChatCommands& c) {
    if (!c.client) return fail("/compact is not available here.");
    if (!c.client->hasHistory()) return ok("(nothing to compact: the conversation is empty)");

    // Tool-free context so the model summarizes instead of editing files.
    Context summarize_ctx;
    const std::string prompt =
        "Summarize the entire conversation so far as a compact, structured note: "
        "the user's goals, decisions made, files read or modified, and the current "
        "state of any in-progress task. Reply with the summary only. " +
        (focus.empty() ? std::string() : "Emphasize: " + focus);
    // Snapshot the conversation so a failed or empty summarization can be
    // rolled back instead of throwing the session away: compaction must never
    // leave you with nothing.
    const auto before = c.client->getHistory();
    // Feed the summarizer a trimmed view of the conversation -- large tool
    // results and file payloads swapped for short placeholders -- so this
    // (the biggest request of the session) stays small and keeps output-token
    // headroom on providers that share one window for input and output (vLLM,
    // Ollama, LM Studio, ...). The live history is untouched: a success
    // replaces it with the summary (beginWithSummary) and a failure restores
    // `before`, so the trimmed copy is never kept either way.
    const auto trimmed = c.client->buildTrimmedHistoryForSummary();
    c.client->loadHistory(trimmed);
    mclog("[/compact] summarization input: " + std::to_string(before.dump().size()) +
          " serialized bytes -> " + std::to_string(trimmed.dump().size()) + " after trimming\n");
    std::string summary;
    try {
        if (c.progress) c.progress("(summarizing the conversation...)");
        summary = c.client->chat(summarize_ctx, prompt);
    } catch (const std::exception& e) {
        // The summarize request was made in-turn, so a failure may have
        // appended stray messages: the untouched conversation comes back.
        c.client->loadHistory(before);
        mclog(std::string("[/compact] FAILED: ") + e.what() + "\n");
        return fail(std::string("compaction failed: ") + e.what());
    }
    mclog("[/compact] raw summary (" + std::to_string(summary.size()) + " bytes):\n" + summary +
          "\n[/compact] --- end of raw summary ---\n");
    // Thinking models (Claude, Gemini) may return the summary inside their
    // reasoning blocks, which the text-only reply drops: that would reseed the
    // conversation with an empty note. Never discard a real session for an
    // empty summary.
    if (summary.find_first_not_of(" \t\r\n") == std::string::npos) {
        c.client->loadHistory(before);
        mclog("[/compact] empty summary; original conversation kept\n");
        return fail("compaction produced no summary; the conversation is kept as it was.");
    }
    c.client->beginWithSummary(summary);
    if (c.history_changed) c.history_changed();
    mclog("[/compact] reseeded the conversation with a " + std::to_string(summary.size()) +
          "-byte summary\n");
    return ok("(conversation compacted)");
}

// --- the folders -------------------------------------------------------------------

ChatCommandResult add_folder(const std::string& args, ChatCommands& c) {
    if (!c.folders) return fail("/add-folder is not available here.");
    FolderSet& folders = *c.folders;
    const ScopeFlags f = parse_scope_flags(args);
    if (!f.error.empty()) return fail(f.error);
    if (f.scope)
        return fail("A folder is granted for this session only, and never saved: run "
                    "/add-folder without " + std::string(scope_flag(*f.scope)) + ".");
    // "/add-folder <path> [ro|rw]": a trailing ro/rw word is the mode,
    // read-only by default. The path may be quoted, so the mode is split off
    // first and the rest unquoted as one argument.
    std::string rest = f.rest;
    bool writable = false;
    if (const std::size_t sp = rest.find_last_of(" \t"); sp != std::string::npos) {
        const std::string mode = lower(rest.substr(sp + 1));
        if (mode == "rw" || mode == "ro") {
            writable = mode == "rw";
            rest = trim(rest.substr(0, sp));
        }
    }
    const std::string arg = unquote(rest);
    if (arg.empty()) return fail("usage: /add-folder <path> [ro|rw]   (read-only unless rw)");
    if (writable && !c.rw_folders)
        return fail(program_name() + " grants folders read-only: it has no editor for the model "
                                     "to change files with. Run /add-folder without rw.");

    const std::size_t before = folders.folders().size();
    std::string label;
    const std::string err = folders.add(arg, &label, writable);
    if (!err.empty()) return fail(err);
    if (folders.folders().size() == before) {
        // Already granted: a repeated grant may still change the mode. The
        // working directory covers its subfolders and has no mode to change.
        const Folder* have = folders.get(label);
        if (have && have->home)
            return ok("That is covered by the working directory ('" + label + "', " +
                      have->root.generic_string() + "), which the model can always read and "
                      "write. Nothing to grant.");
        if (have && have->writable != writable) {
            folders.set_writable(label, writable);
            if (c.folders_changed) c.folders_changed();
            return ok("'" + label + "' is now " + (writable ? "read-write." : "read-only."));
        }
        return ok("Already granted, as '" + label + "' (" +
                  (have && have->writable ? "read-write" : "read-only") + ").");
    }
    if (c.folders_changed) c.folders_changed();
    return ok(std::string("Granted ") + (writable ? "read-write" : "read-only") + " access to " +
              arg + " as '" + label + "', for this session. The model can now list, read and "
              "search it" +
              (writable ? ", and create or edit files under it with the editor tool, as "
                          "<label>/<path> or by absolute path. "
                        : "; it cannot change anything. ") +
              (folders.folders().size() == (folders.home() ? 2u : 1u)
                   ? std::string("Revoke with /remove-folder ") + label + "."
                   : "Files are addressed as <label>/<path>; /list-folders shows the labels."));
}

ChatCommandResult remove_folder(const std::string& args, ChatCommands& c) {
    if (!c.folders) return fail("/remove-folder is not available here.");
    FolderSet& folders = *c.folders;
    const ScopeFlags f = parse_scope_flags(args);
    if (!f.error.empty()) return fail(f.error);
    if (f.scope)
        return fail("Folders are never saved, so there is nothing to remove from a config: run "
                    "/remove-folder without " + std::string(scope_flag(*f.scope)) + ".");
    const std::string arg = unquote(f.rest);
    if (arg.empty())
        return fail("usage: /remove-folder <path or label>\n\n" + list_folders_text(folders));
    if (const Folder* have = folders.get(arg); have && have->home)
        return fail("'" + arg + "' is the working directory " + program_name() +
                    " was started in; it cannot be removed or made read-only.");
    if (const Folder* have = folders.get(arg); have && have->system)
        return fail("'" + have->label + "' is " + program_name() + "'s own folder (" + have->note +
                    "), not a grant; it cannot be removed.");
    if (!folders.remove(arg))
        return fail("'" + arg + "' is not a granted folder.\n\n" + list_folders_text(folders));
    if (c.folders_changed) c.folders_changed();
    return ok("Revoked '" + arg + "'. " +
              (folders.has_grants() ? "\n" + list_folders_text(folders)
                                    : folders.home()
                                          ? std::string("The model reaches only the working "
                                                        "directory now.")
                                          : std::string("The model reaches no folder now.")));
}

} // namespace

ScopeFlags parse_scope_flags(const std::string& args, bool leading_only) {
    ScopeFlags out;
    std::string kept;
    std::size_t i = 0;
    while (i < args.size()) {
        const std::size_t b = args.find_first_not_of(" \t", i);
        if (b == std::string::npos) break;
        std::size_t e = args.find_first_of(" \t", b);
        if (e == std::string::npos) e = args.size();
        const std::string word = args.substr(b, e - b);
        std::optional<SettingScope> s;
        if (word == "--session") s = SettingScope::Session;
        else if (word == "--project") s = SettingScope::Project;
        else if (word == "--global") s = SettingScope::Global;
        if (s) {
            if (out.scope && *out.scope != *s)
                out.error = std::string("Give one scope, not both ") + scope_flag(*out.scope) +
                            " and " + scope_flag(*s) + ".";
            out.scope = s;
        } else {
            if (leading_only) {
                // The rest is the command's own text, as it was written.
                kept = args.substr(b);
                break;
            }
            kept += args.substr(i, e - i);
        }
        i = e;
    }
    out.rest = trim(kept);
    return out;
}

const char* scope_flag(SettingScope scope) {
    switch (scope) {
    case SettingScope::Session: return "--session";
    case SettingScope::Project: return "--project";
    case SettingScope::Global: return "--global";
    }
    return "";
}

std::string setting_origin(const std::string& key) {
    for (const auto& e : effective_config()) {
        if (e.key != key || e.value.empty()) continue;
        std::string s = level_phrase(e.origin);
        if (e.origin != Level::Policy)
            s += e.program_key ? ", for " + program_name() + " only" : ", for all programs";
        return s;
    }
    return "";
}

SettingWrite write_setting(const std::string& key, const std::optional<std::string>& value,
                           SettingScope scope) {
    SettingWrite w;
    if (scope == SettingScope::Session) {
        w.text = "a session's setting is not saved";
        return w;
    }
    // Policy is applied last: a write would succeed and change nothing, which
    // is worse than refusing, since the user would think it took.
    if (is_policy_managed(key)) {
        w.text = key + " is set by your organization's policy (" + policy_source() +
                 "), so it is not changed here";
        return w;
    }
    const Level level = level_of(scope);
    const auto path = config_path(level);
    if (path.empty()) {
        w.text = "there is no " + std::string(level_phrase(level)) + " (the working directory "
                 "could not be read)";
        return w;
    }
    try {
        Config cfg = Config::load(path);
        // The key that sets the value at this scope: the program's own when
        // the scope has it, else the shared one.
        const std::string own = program_name() + "." + key;
        const bool program_key = cfg.get(own).has_value();
        const std::string target = program_key ? own : key;
        if (value) {
            cfg.set(target, *value);
        } else if (!cfg.unset(target)) {
            w.text = key + " is not set in the " + std::string(level_phrase(level));
            return w;
        }
        cfg.save(path);
        w.ok = true;
        w.text = std::string(level_phrase(level)) + ", for " +
                 (program_key ? program_name() + " only" : std::string("all programs"));
    } catch (const std::exception& e) {
        w.text = std::string("could not save it: ") + e.what();
    }
    return w;
}

std::optional<ChatCommandResult> run_chat_command(const std::string& line_in, ChatCommands& c) {
    const std::string line = trim(line_in);
    if (auto a = args_of(line, "cot")) return cot(*a, c);
    if (auto a = args_of(line, "effort")) return effort(*a, c);
    if (auto a = args_of(line, "clear")) {
        if (!a->empty()) return fail("usage: /clear");
        return clear(c);
    }
    if (auto a = args_of(line, "compact")) return compact(*a, c);
    if (auto a = args_of(line, "list-folders")) {
        if (!c.folders) return fail("/list-folders is not available here.");
        return ok(list_folders_text(*c.folders));
    }
    if (auto a = args_of(line, "add-folder")) return add_folder(*a, c);
    if (auto a = args_of(line, "remove-folder")) return remove_folder(*a, c);
    return std::nullopt;
}

std::string chat_commands_help(const ChatCommands& c) {
    std::string out;
    auto line = [&](const char* cmd, const char* what) {
        std::string l = std::string("  ") + cmd;
        if (l.size() < 34) l.append(34 - l.size(), ' ');
        out += l + " " + what + "\n";
    };
    if (c.ai) {
        line("/cot [on|off|unset]", "show the model's intermediate text (default: global)");
        if (!c.provider_name.empty())
            line("/effort [<level>|unset]", "reasoning effort, openai dialect (default: project)");
    }
    if (c.client) {
        line("/clear", "start the conversation over");
        line("/compact [<focus>]", "replace the conversation with a summary of it");
    }
    if (c.folders) {
        line("/list-folders", "the folders the model reaches");
        line(c.rw_folders ? "/add-folder <path> [ro|rw]" : "/add-folder <path>",
             "grant a folder, for this session");
        line("/remove-folder <path|label>", "take a grant away");
    }
    if (c.ai)
        out += "  Settings take --session, --project or --global to say where they go;\n"
               "  unset removes one there.\n";
    return out;
}

std::string list_folders_text(const FolderSet& folders) {
    if (folders.empty()) return "No folders are granted. Grant one with /add-folder <path> [ro|rw].";
    std::ostringstream out;
    out << "The model can reach these folders:\n";
    for (const auto& f : folders.folders()) {
        out << "  " << f.label << "  ->  " << f.root.generic_string()
            << (f.home ? std::string("  (working directory, read-write)")
                : f.system
                    ? "  (" + program_name() + "'s: " + f.note +
                          (f.writable ? ", read-write)" : ", read-only)")
                : f.writable ? std::string("  (read-write)")
                             : std::string("  (read-only)"))
            << "\n";
    }
    if (!folders.has_grants())
        out << "No other folders are granted. Grant one with /add-folder <path> [ro|rw].";
    std::string s = out.str();
    if (!s.empty() && s.back() == '\n') s.pop_back();
    return s;
}

} // namespace tapto

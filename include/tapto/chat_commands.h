// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#pragma once

#include <functional>
#include <optional>
#include <string>

class AiBackend; // tapto/aibackend.h, tapto/aiconfig.h: outside the namespace
class AiConfig;

namespace tapto {

class FolderSet;

// ---------------------------------------------------------------------------
// The commands every tapto program offers the user, written once:
//
//   /cot [on|off|unset]            show the model's intermediate text or not
//   /effort [<level>|unset]        the reasoning effort (openai dialect)
//   /clear                         start the conversation over
//   /compact [<focus>]             replace it with a summary of itself
//   /list-folders                  the folders the model reaches
//   /add-folder <path> [ro|rw]     grant one, for this session
//   /remove-folder <path|label>    take a grant away
//
// A program hands a typed line to run_chat_command() first, and runs what
// comes back as nullopt itself (tapto-code's /add-command, /resume, ...).
// Every command returns its text; the program shows it its own way.
//
// --- Where a setting goes --------------------------------------------------
//
// A settings command writes to one scope: the session (nothing saved), the
// project's config, or the global one. Each has a default (/cot global,
// /effort the project's), changed with --session, --project or --global,
// anywhere on the line. `unset` removes the key at that scope, so a less
// specific one applies again; a bare command shows the value in force and
// where it comes from. Folders are never saved: a grant of file access does
// not outlive the session it was given in.
//
// The config is shared by the tapto programs, and a key may be one
// program's ("tapto-word.print-cot", tapto/program.h). A write goes to the
// key that set the value in force at that scope, the program's own when that
// is what the scope has, else the shared one, so a split made by hand stays.
// A key the organization's policy sets is not written: it would change
// nothing.
// ---------------------------------------------------------------------------

enum class SettingScope { Session, Project, Global };

// The scope flags taken out of a command's arguments.
struct ScopeFlags {
    std::optional<SettingScope> scope; // none given
    std::string rest;                  // the arguments without them, trimmed
    std::string error;                 // two scopes, say
};

// Reads --session, --project and --global out of `args`, anywhere, or with
// `leading_only` only before the first other word: what follows that is the
// command's own text, as written (tapto-code's /add-command).
ScopeFlags parse_scope_flags(const std::string& args, bool leading_only = false);

const char* scope_flag(SettingScope scope); // "--global"

// Where the value in force of `key` comes from, for a reply: "global config,
// for all programs", "project config, for tapto-word only", "your
// organization's policy", ... Empty when the key is not set anywhere.
std::string setting_origin(const std::string& key);

// Writes `value` to `key` at `scope` (Project or Global), or removes it
// (nullopt), as described above.
struct SettingWrite {
    bool ok = false;
    std::string text; // ok: where it went ("global config, for all programs"); else why not
};
SettingWrite write_setting(const std::string& key, const std::optional<std::string>& value,
                           SettingScope scope);

// What a program gives the shared commands. Each part is optional: a command
// whose part is missing says it is not available here.
struct ChatCommands {
    AiConfig* ai = nullptr;      // /cot, /effort act on it
    AiBackend* client = nullptr; // /clear, /compact
    FolderSet* folders = nullptr;
    std::string provider_name;    // for <name>-reasoning-effort
    std::string provider_dialect; // /effort applies to openai alone
    bool has_project = true;      // false: --project is refused
    bool rw_folders = true;       // false: /add-folder grants read-only only

    // tapto-code keeps the conversation for /resume; what it returns is added
    // to the reply ("; /resume brings it back").
    std::function<std::string()> before_clear;
    // The conversation changed (cleared, compacted): save it.
    std::function<void()> history_changed;
    // The folder set changed: rebuild the tools and the prompt.
    std::function<void()> folders_changed;
    // A line to show while a command works ("summarizing the conversation").
    std::function<void(const std::string&)> progress;
};

struct ChatCommandResult {
    std::string text;
    bool error = false;
};

// Runs `line` when it is one of the commands above; nullopt otherwise.
std::optional<ChatCommandResult> run_chat_command(const std::string& line, ChatCommands& c);

// The commands above for /help, one per line, indented by two.
std::string chat_commands_help(const ChatCommands& c);

// /list-folders' text.
std::string list_folders_text(const FolderSet& folders);

} // namespace tapto

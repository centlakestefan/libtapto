// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#include "tapto/commands.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cwctype>
#include <filesystem>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  define NOMINMAX
#  include <windows.h>
#else
#  include <unistd.h>
#  include <sys/stat.h>
#  include <sys/wait.h>
extern char** environ;
#endif

#include <nlohmann/json.hpp>

#include "tapto/config.h"
#include "tapto/context.h"
#include "tapto/overflow.h"
#include "tapto/pathrules.h"
#include "tapto/policy.h"
#include "tapto/program.h"

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace tapto {

std::map<std::string, std::string> merged_commands() {
    std::map<std::string, std::string> out;
    for (const auto& e : effective_commands()) out[e.name] = e.command;
    return out;
}

std::vector<CommandEntry> effective_commands() {
    std::vector<CommandEntry> merged;
    auto apply = [&](const std::vector<Config::Entry>& entries, Level lvl) {
        for (const auto& e : entries) {
            bool found = false;
            for (auto& existing : merged) {
                if (existing.name == e.first) {
                    existing.command = e.second;
                    existing.origin = lvl;
                    found = true;
                    break;
                }
            }
            if (!found) merged.push_back({e.first, e.second, lvl});
        }
    };
    // The user's stores count only while policy lets them. Either way the
    // organization's commands come last and win, so a name it defines cannot
    // be redefined below it.
    if (policy_allows_user_commands()) {
        for (Level lvl : {Level::System, Level::Global, Level::Local}) {
            apply(Config::load(commands_path(lvl)).entries(), lvl);
        }
    }
    apply(policy_commands(), Level::Policy);
    return merged;
}

std::vector<CommandEntry> commands_in_scope(Level level) {
    std::vector<CommandEntry> out;
    const std::vector<Config::Entry> entries =
        (level == Level::Policy) ? policy_commands() : Config::load(commands_path(level)).entries();
    for (const auto& e : entries) {
        out.push_back({e.first, e.second, level});
    }
    return out;
}

std::string command_policy_refusal(const std::string& name) {
    if (!policy_allows_user_commands()) {
        return "your organization's policy allows only the commands it defines; '" + name +
               "' cannot be added";
    }
    for (const auto& e : policy_commands()) {
        if (e.first == name) {
            return "'" + name + "' is defined by your organization's policy and cannot be redefined";
        }
    }
    return "";
}

const char* const kReadOnlyMark = "[ro]";

namespace {

// Where the mark ends (the template's first character), or npos when the
// command line has no mark: "[ro]" first, alone or before whitespace.
std::size_t after_read_only_mark(const std::string& cmdline) {
    const std::string mark = kReadOnlyMark;
    const std::size_t start = cmdline.find_first_not_of(" \t");
    if (start == std::string::npos || cmdline.compare(start, mark.size(), mark) != 0) {
        return std::string::npos;
    }
    const std::size_t end = start + mark.size();
    if (end < cmdline.size() && cmdline[end] != ' ' && cmdline[end] != '\t') return std::string::npos;
    const std::size_t rest = cmdline.find_first_not_of(" \t", end);
    return rest == std::string::npos ? cmdline.size() : rest;
}

// The first unquoted '#', or npos. A '#' inside double quotes is a literal
// character of an argument, the way the template tokenizer reads it, so it
// must not start a note: `grep -n "#TODO" f` keeps its quoted '#'.
std::size_t note_start(const std::string& s) {
    bool in_quotes = false;
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '"') { in_quotes = !in_quotes; continue; }
        if (!in_quotes && s[i] == '#') return i;
    }
    return std::string::npos;
}

// A note is at the end of the stored value and never runs, so the command line
// is what is before it: the program and its placeholders only. The space
// before the '#' is not part of the command line either, so it is trimmed.
std::string command_line(const std::string& cmdline) {
    const std::size_t at = note_start(cmdline);
    std::string line = (at == std::string::npos) ? cmdline : cmdline.substr(0, at);
    while (!line.empty() && (line.back() == ' ' || line.back() == '\t')) line.pop_back();
    return line;
}

} // namespace

bool command_reads_only(const std::string& cmdline) {
    return after_read_only_mark(cmdline) != std::string::npos;
}

std::string command_template(const std::string& cmdline) {
    // Drop the trailing note first (a hint, not part of the command line),
    // then the leading [ro] mark: what is run.
    const std::string line = command_line(cmdline);
    const std::size_t rest = after_read_only_mark(line);
    return rest == std::string::npos ? line : line.substr(rest);
}

std::string command_note(const std::string& cmdline) {
    const std::size_t at = note_start(cmdline);
    if (at == std::string::npos) return "";
    std::string note = cmdline.substr(at + 1);
    const std::size_t b = note.find_first_not_of(" \t");
    if (b == std::string::npos) return "";
    const std::size_t e = note.find_last_not_of(" \t\r\n");
    return note.substr(b, e - b + 1);
}

std::string command_line_refusal(const std::string& cmdline_with_mark) {
    // The refusal is about the command line that would run; the trailing note
    // is a hint and never runs, so shell syntax in it is no refusal.
    const std::string cmdline = command_template(cmdline_with_mark);
    if (cmdline.find_first_not_of(" \t") == std::string::npos) {
        return "the command line names no program";
    }
    // Only outside double quotes: a quoted "a|b" is one literal argument, the
    // way the template tokenizer reads it.
#ifdef _WIN32
    const char* const shell = "|<>&`";
#else
    const char* const shell = "|<>&`;";
#endif
    bool in_quotes = false;
    for (char c : cmdline) {
        if (c == '"') { in_quotes = !in_quotes; continue; }
        // (strchr finds the terminator too, so a NUL is excluded by hand.)
        if (in_quotes || c == 0 || std::strchr(shell, c) == nullptr) continue;
        return std::string("the command line uses shell syntax ('") + c +
               "'), and commands are not run through a shell. Put the command line in a "
               "script in " + machine_script_folder().u8string() +
               (policy_allows_user_commands() ? " or " + user_script_folder().u8string() : "") +
               " and name the script instead";
    }
    return "";
}

std::filesystem::path machine_script_folder() {
    for (const auto& e : policy_entries()) {
        // Only an absolute path: a relative one would mean a different folder
        // in every project.
        if (e.first != "script-folder") continue;
        const auto p = std::filesystem::u8path(e.second);
        if (p.is_absolute()) return p;
    }
#ifdef _WIN32
    wchar_t buf[MAX_PATH];
    const DWORD n = GetEnvironmentVariableW(L"ProgramFiles", buf, MAX_PATH);
    const std::filesystem::path pf =
        (n > 0 && n < MAX_PATH) ? std::filesystem::path(std::wstring(buf, n))
                                : std::filesystem::path(L"C:\\Program Files");
    return pf / "Centlake" / "tapto" / "scripts";
#else
    return "/etc/tapto/scripts";
#endif
}

std::filesystem::path user_script_folder() {
    return global_dir() / "scripts";
}

void add_command(Level level, const std::string& name, const std::string& command) {
    if (level == Level::Policy) throw std::invalid_argument("the policy scope is read-only");
    auto path = commands_path(level);
    Config store = Config::load(path);
    store.set(name, command);
    store.save(path);
}

bool remove_command(Level level, const std::string& name) {
    if (level == Level::Policy) return false;
    auto path = commands_path(level);
    Config store = Config::load(path);
    if (!store.unset(name)) return false;
    store.save(path);
    return true;
}

// --- the command tools ----------------------------------------------------

namespace {

// True if `path` is `root` or under it, both already canonical.
bool is_under(const fs::path& root, const fs::path& path) {
    const fs::path rel = path.lexically_relative(root);
    return !rel.empty() && *rel.begin() != fs::path("..");
}

// One path component compared the way the filesystem would: Windows is
// case-insensitive, so ".EXE" is ".exe" there.
bool component_is(const fs::path& part, const char* name) {
#ifdef _WIN32
    const std::string s = part.string();
    const size_t n = std::strlen(name);
    if (s.size() != n) return false;
    for (size_t i = 0; i < n; ++i) {
        if (std::tolower(static_cast<unsigned char>(s[i])) !=
            std::tolower(static_cast<unsigned char>(name[i])))
            return false;
    }
    return true;
#else
    return part == fs::path(name);
#endif
}

// A path made canonical where it exists and tidied where it doesn't, so two
// spellings of one folder compare equal.
fs::path canonical_or_normal(const fs::path& p) {
    std::error_code ec;
    fs::path c = fs::weakly_canonical(p, ec);
    return ec ? p.lexically_normal() : c;
}

// is_under with the filesystem's idea of case: on Windows a folder that does
// not exist yet keeps the case it was written in.
bool is_within(const fs::path& root, const fs::path& path) {
#ifdef _WIN32
    auto lower = [](const fs::path& p) {
        std::wstring s = p.wstring();
        for (wchar_t& c : s) c = static_cast<wchar_t>(std::towlower(c));
        return fs::path(s);
    };
    return is_under(lower(root), lower(path));
#else
    return is_under(root, path);
#endif
}

// --- command tools (allow-listed) -----------------------------------------

// --- finding a command's program --------------------------------------------
//
// The allow-list fixes a command's text, not the program that text ends up
// starting. CreateProcess and cmd.exe both look in the current directory
// before PATH, and the current directory is the sandbox, which the model can
// write to: a `nmake.bat` it created there ran instead of the real nmake. So
// the program is looked up here, by a search that skips every folder the model
// could have put it in, and started by its absolute path. Nothing is handed to
// a shell to parse either: a command that needs pipes or redirection names a
// script in a script folder (commands.h), which only an administrator, or the
// user, can write.

#ifdef _WIN32
// True when this process can change the file or folder at `p`: write to it,
// add to it, delete it, or rewrite its permissions. Asked of the access check
// rather than worked out from the ACL here, so group membership, deny entries
// and inheritance are Windows' to judge. Anything that can't be checked counts
// as writable.
bool token_can_write(const fs::path& p) {
    std::error_code ec;
    const bool dir = fs::is_directory(p, ec);
    const DWORD need = dir ? (FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD |
                              DELETE | WRITE_DAC | WRITE_OWNER)
                           : (FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE | WRITE_DAC | WRITE_OWNER);
    const SECURITY_INFORMATION what =
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    DWORD size = 0;
    GetFileSecurityW(p.c_str(), what, nullptr, 0, &size);
    if (size == 0) return true;
    std::vector<unsigned char> sd(size);
    if (!GetFileSecurityW(p.c_str(), what, sd.data(), size, &size)) return true;

    HANDLE process = nullptr, token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &process)) return true;
    const BOOL dup = DuplicateToken(process, SecurityImpersonation, &token);
    CloseHandle(process);
    if (!dup) return true;

    GENERIC_MAPPING mapping = {FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE,
                               FILE_ALL_ACCESS};
    PRIVILEGE_SET privileges{};
    DWORD privileges_size = sizeof(privileges);
    DWORD granted = 0;
    BOOL status = FALSE;
    const BOOL ok = AccessCheck(sd.data(), token, MAXIMUM_ALLOWED, &mapping, &privileges,
                                &privileges_size, &granted, &status);
    CloseHandle(token);
    if (!ok) return true;
    return status && (granted & need) != 0;
}

// An elevated process can rewrite policy itself, so guarding the machine's
// script folder against it would protect nothing.
bool process_is_elevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    const BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated;
}
#else
// True when this process can change the file or folder at `p`: it may write
// to it, or it owns it and so may make it writable.
bool token_can_write(const fs::path& p) {
    struct stat st{};
    if (stat(p.c_str(), &st) != 0) return true;
    return st.st_uid == geteuid() || access(p.c_str(), W_OK) == 0;
}

bool process_is_elevated() { return geteuid() == 0; }
#endif

// True if the model could have put a file at `p`: the editor would write
// there (the working directory or a read-write grant, minus the git
// directory and the programs' own folders), and the operating system would
// let it. The second half is what keeps a tool on PATH usable when the
// working directory is the root of a drive, where System32 is inside it but
// no more writable than ever.
bool agent_could_plant(const PathRules& rules, const fs::path& p) {
    const fs::path home = rules.root();
    if ((home.empty() || !is_within(home, p)) && !rules.owner(p, /*writable_only=*/true))
        return false;
    std::string ignored;
    if (rules.refuse_protected_write(p, p.u8string(), ignored)) return false;
    return token_can_write(p);
}

// The machine's script folder speaks for the organization, so the user must
// not be able to change it either: not the script (it would change what a
// policy command does) and not the folder (a new script there would stand in
// for a program on PATH). Administrators create it under Program Files, whose
// inherited permissions give users read and execute only.
bool machine_script_trusted(const fs::path& dir, const fs::path& file) {
    if (process_is_elevated()) return true;
    return !token_can_write(dir) && !token_can_write(file);
}

// One entry of PATH per element, as written: unquoted, and without the empty
// and relative entries, which mean "the current directory".
std::vector<fs::path> path_entries() {
#ifdef _WIN32
    std::wstring value;
    if (const DWORD n = GetEnvironmentVariableW(L"PATH", nullptr, 0); n > 0) {
        value.resize(n);
        value.resize(GetEnvironmentVariableW(L"PATH", value.data(), n));
    }
    const wchar_t sep = L';';
#else
    const char* raw = std::getenv("PATH");
    const std::string value = raw ? raw : "";
    const char sep = ':';
#endif
    std::vector<fs::path> out;
    size_t start = 0;
    while (start <= value.size()) {
        size_t end = value.find(sep, start);
        if (end == value.npos) end = value.size();
        auto entry = value.substr(start, end - start);
#ifdef _WIN32
        entry.erase(std::remove(entry.begin(), entry.end(), L'"'), entry.end());
#endif
        const fs::path p(entry);
        if (!entry.empty() && p.is_absolute()) out.push_back(p);
        start = end + 1;
    }
    return out;
}

// A program found for a command.
struct Program {
    fs::path path;
    // Run through the shell as a script: a .bat/.cmd on Windows; elsewhere a
    // .sh without the execute bit (one with it runs by its #! line).
    bool script = false;
};

bool ext_is(const fs::path& p, const char* ext) {
    return component_is(p.extension(), ext);
}

#ifdef _WIN32
// The only kinds of file a command may start, which is also what a bare name
// is completed with, in PATHEXT's order. A .ps1, .vbs or .js would need an
// interpreter's own rules; a wrapper .cmd can start one if it must.
bool runnable_ext(const fs::path& ext) {
    for (const char* e : {".exe", ".com", ".bat", ".cmd"}) {
        if (component_is(ext, e)) return true;
    }
    return false;
}

std::vector<std::wstring> name_suffixes() {
    std::vector<std::wstring> out;
    wchar_t buf[1024];
    const DWORD n = GetEnvironmentVariableW(L"PATHEXT", buf, 1024);
    const std::wstring value = (n > 0 && n < 1024) ? std::wstring(buf, n) : L".COM;.EXE;.BAT;.CMD";
    size_t start = 0;
    while (start <= value.size()) {
        size_t end = value.find(L';', start);
        if (end == value.npos) end = value.size();
        const std::wstring ext = value.substr(start, end - start);
        if (!ext.empty() && runnable_ext(fs::path(ext))) out.push_back(ext);
        start = end + 1;
    }
    if (out.empty()) out = {L".com", L".exe", L".bat", L".cmd"};
    return out;
}
#endif

// The files `name` could mean in `dir`, in the order they are tried, each
// with whether it runs as a script. A file that can't be run is left out.
std::vector<Program> candidates(const fs::path& dir, const fs::path& name) {
    std::vector<Program> out;
    std::error_code ec;
#ifdef _WIN32
    std::vector<fs::path> files;
    if (runnable_ext(name.extension())) {
        files.push_back(dir / name);
    } else {
        for (const auto& ext : name_suffixes()) files.push_back(dir / (name.wstring() + ext));
    }
    for (const auto& f : files) {
        if (!fs::is_regular_file(f, ec)) continue;
        out.push_back({f, ext_is(f, ".bat") || ext_is(f, ".cmd")});
    }
#else
    const fs::path f = dir / name;
    if (fs::is_regular_file(f, ec)) {
        if (access(f.c_str(), X_OK) == 0) out.push_back({f, false});
        else if (ext_is(f, ".sh")) out.push_back({f, true});
    }
#endif
    return out;
}

// Find the program `name` names. A path (`build/tests`, `./configure`, an
// absolute one) is taken as written, relative to `cwd`: the command's author
// chose that file, and trusting a file in the tree is the trust allow-listing
// a build already is (see the README). A bare name is looked up in the script
// folders and then on PATH, skipping any folder the model could have written
// to — which is the hole this closes: it is the bare name an attacker shadows.
bool find_program(const PathRules& rules, const std::string& name, const fs::path& cwd,
                  Program& out, std::string& error) {
    const fs::path np = fs::u8path(name);
    if (np.empty()) { error = "ERROR: empty command"; return false; }

    if (np.has_parent_path() || np.is_absolute()) {
        const fs::path full = canonical_or_normal(np.is_absolute() ? np : cwd / np);
        const auto found = candidates(full.parent_path(), full.filename());
        if (found.empty()) {
            error = "ERROR: '" + name + "' was not found, or is not something " + program_name() + " can run.";
            return false;
        }
        out = found.front();
        return true;
    }

    const fs::path machine = canonical_or_normal(machine_script_folder());
    std::vector<fs::path> dirs = {machine};
    if (policy_allows_user_commands()) dirs.push_back(canonical_or_normal(user_script_folder()));
    for (const auto& p : path_entries()) dirs.push_back(canonical_or_normal(p));

    std::string ignored;
    for (const auto& dir : dirs) {
        const auto found = candidates(dir, np);
        if (found.empty()) continue;
        const Program& prog = found.front();
        if (agent_could_plant(rules, dir) || agent_could_plant(rules, prog.path)) {
            if (ignored.empty()) ignored = prog.path.u8string();
            continue;
        }
        if (is_within(machine, prog.path) && !machine_script_trusted(dir, prog.path)) {
            error = "ERROR: '" + prog.path.u8string() + "' is in the machine's script folder, "
                    "but this account can change it, so it cannot speak for the organization. "
                    "An administrator has to make the folder and its scripts read-only to "
                    "users.";
            return false;
        }
        out = prog;
        return true;
    }

    error = "ERROR: '" + name + "' was not found in the script folders or on PATH.";
    if (!ignored.empty()) {
        error += " A copy at '" + ignored + "' was ignored: it is in a folder the agent can "
                 "write to, so the agent could have put it there.";
    }
#ifdef _WIN32
    error += " A cmd.exe built-in (dir, echo, copy, ...) or a command line with pipes or "
             "redirection has to be a .cmd script in " + machine.u8string() +
             (policy_allows_user_commands() ? " or " + user_script_folder().u8string() : "") +
             ", named by the command.";
#endif
    return false;
}

// PATH for a command's process, without the folders the model could write
// to: a script, or a build tool, starts programs of its own by name.
#ifdef _WIN32
std::wstring child_path(const PathRules& rules) {
    std::wstring out;
    for (const auto& p : path_entries()) {
        if (agent_could_plant(rules, canonical_or_normal(p))) continue;
        if (!out.empty()) out += L';';
        out += p.wstring();
    }
    return out;
}
#else
std::string child_path(const PathRules& rules) {
    std::string out;
    for (const auto& p : path_entries()) {
        if (agent_could_plant(rules, canonical_or_normal(p))) continue;
        if (!out.empty()) out += ':';
        out += p.string();
    }
    return out;
}
#endif

// Split a (trusted, author-written) command template into tokens, honoring
// simple double-quote grouping so a token may contain spaces.
std::vector<std::string> tokenize_template(const std::string& s) {
    std::vector<std::string> toks;
    std::string cur;
    bool in_quotes = false, have = false;
    for (char c : s) {
        if (c == '"') { in_quotes = !in_quotes; have = true; }
        else if (!in_quotes && (c == ' ' || c == '\t')) {
            if (have) { toks.push_back(cur); cur.clear(); have = false; }
        } else { cur.push_back(c); have = true; }
    }
    if (have) toks.push_back(cur);
    return toks;
}

// Parse a placeholder at s[i] (s[i] must be '%'). Recognizes %n, %*, %pn, %p*.
// Returns characters consumed (0 if not a placeholder). The 'p' type marks a
// path argument; either is_star or index (1-9) is set.
size_t parse_placeholder(const std::string& s, size_t i, bool& is_path, bool& is_star, int& index) {
    is_path = false;
    is_star = false;
    index = 0;
    size_t j = i + 1; // s[i] == '%'
    if (j >= s.size()) return 0;
    if (s[j] == 'p') { is_path = true; ++j; if (j >= s.size()) return 0; }
    if (s[j] == '*') { is_star = true; return j - i + 1; }
    if (s[j] >= '1' && s[j] <= '9') { index = s[j] - '0'; return j - i + 1; }
    return 0;
}

// Expand a template into an argv vector. The template's whitespace defines the
// argv boundaries; %n / %pn are replaced with model-supplied values as *literal*
// argv elements (never re-split), so no shell quoting is involved. The 'p'
// (path) type additionally requires the value to resolve inside the sandbox and
// substitutes the resolved absolute path. %* / %p* take all remaining values.
// `reads_only` is a command marked [ro]: its paths may be in read-only grants.
bool build_argv(const PathRules& rules, const std::string& tpl, const std::vector<std::string>& args,
                const fs::path& base, std::vector<std::string>& argv, std::string& error,
                bool reads_only = false) {
    // Highest positional index used; %* expands to the args beyond it.
    int max_idx = 0;
    bool has_star = false;
    for (size_t i = 0; i < tpl.size(); ++i) {
        if (tpl[i] != '%') continue;
        bool p, star;
        int idx;
        if (parse_placeholder(tpl, i, p, star, idx) > 0) {
            if (!star) max_idx = std::max(max_idx, idx);
            else has_star = true;
        }
    }

    // A template with no %* / %p* has a fixed number of slots; more supplied
    // values than slots is a model error (e.g. git-commit given ["-m","text"]
    // would stuff "-m" into %1 and silently drop "text"), so refuse it rather
    // than silently consume the wrong values.
    if (!has_star && static_cast<int>(args.size()) > max_idx) {
        error = "ERROR: command takes " + std::to_string(max_idx) +
                " argument" + (max_idx == 1 ? "" : "s") +
                " but " + std::to_string(args.size()) + " were provided. "
                "Extra values would be silently ignored, so the call was rejected.";
        return false;
    }

    // A %p value is a path the command may write to (a formatter's -i target,
    // a copy's destination), so it is held to what the editor is held to: the
    // sandbox, and never a git directory. It resolves against `base`, the
    // directory the command will run in, so a relative value means the same
    // file to the model, to the built-ins and to the process itself. A [ro]
    // command only reads, so its paths may also be in read-only grants; the
    // protected folders stay refused, since the mark is a promise the program
    // cannot check.
    const PathScope path_scope = reads_only ? PathScope::Read : PathScope::Write;
    auto subst_path = [&](const std::string& value, std::string& out) -> bool {
        fs::path resolved;
        std::string perr;
        if (!rules.resolve(value, resolved, perr, base, path_scope)) { error = perr; return false; }
        const bool program_read = reads_only && rules.in_read_only_program_folder(resolved);
        if (!program_read && rules.refuse_protected_write(resolved, value, perr)) { error = perr; return false; }
        out = resolved.string();
        return true;
    };

    for (const std::string& tok : tokenize_template(tpl)) {
        if (tok == "%*" || tok == "%p*") {
            bool as_path = (tok == "%p*");
            for (size_t i = static_cast<size_t>(max_idx); i < args.size(); ++i) {
                if (as_path) {
                    std::string r;
                    if (!subst_path(args[i], r)) return false;
                    argv.push_back(r);
                } else {
                    argv.push_back(args[i]);
                }
            }
            continue;
        }

        std::string out;
        for (size_t i = 0; i < tok.size();) {
            if (tok[i] == '%') {
                bool is_path, is_star;
                int index;
                size_t consumed = parse_placeholder(tok, i, is_path, is_star, index);
                if (consumed > 0 && !is_star) {
                    if (static_cast<size_t>(index) > args.size()) {
                        error = "ERROR: command needs argument %" +
                                std::string(is_path ? "p" : "") + std::to_string(index) +
                                " but only " + std::to_string(args.size()) + " were provided.";
                        return false;
                    }
                    if (is_path) {
                        std::string r;
                        if (!subst_path(args[index - 1], r)) return false;
                        out += r;
                    } else {
                        out += args[index - 1];
                    }
                    i += consumed;
                    continue;
                }
            }
            out.push_back(tok[i]);
            ++i;
        }
        argv.push_back(out);
    }
    if (argv.empty()) { error = "ERROR: empty command"; return false; }
    return true;
}

std::string join_argv(const std::vector<std::string>& argv) {
    std::string s;
    for (size_t i = 0; i < argv.size(); ++i) { if (i) s += ' '; s += argv[i]; }
    return s;
}

#ifdef _WIN32
std::wstring utf8_to_wide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    return w;
}

// Quote one argument per the CommandLineToArgvW rules so the child receives it
// as a single, literal argv element.
std::string win_quote_arg(const std::string& a) {
    if (!a.empty() && a.find_first_of(" \t\n\v\"") == std::string::npos) return a;
    std::string out = "\"";
    for (size_t i = 0;; ++i) {
        size_t bs = 0;
        while (i < a.size() && a[i] == '\\') { ++bs; ++i; }
        if (i == a.size()) { out.append(bs * 2, '\\'); break; }
        if (a[i] == '"') { out.append(bs * 2 + 1, '\\'); out.push_back('"'); }
        else { out.append(bs, '\\'); out.push_back(a[i]); }
    }
    out.push_back('"');
    return out;
}

bool env_name_is(const std::wstring& var, const wchar_t* name) {
    const size_t n = std::wcslen(name);
    if (var.size() <= n || var[n] != L'=') return false;
    for (size_t i = 0; i < n; ++i) {
        if (std::towlower(var[i]) != std::towlower(name[i])) return false;
    }
    return true;
}

// The environment block a command runs with: ours, with PATH stripped of the
// folders the model could write to (child_path), and with
// NoDefaultCurrentDirectoryInExePath set, which stops cmd.exe -- running a
// script, or started by a build -- and anything else that asks Windows
// (NeedCurrentDirectoryForExePath) from looking in the current directory for
// a program, the very lookup a planted nmake.bat relied on.
std::vector<wchar_t> child_environment(const PathRules& rules) {
    std::vector<std::wstring> vars;
    if (LPWCH block = GetEnvironmentStringsW()) {
        for (LPWCH p = block; *p; p += std::wcslen(p) + 1) vars.emplace_back(p);
        FreeEnvironmentStringsW(block);
    }
    const wchar_t* const no_cwd = L"NoDefaultCurrentDirectoryInExePath";
    vars.erase(std::remove_if(vars.begin(), vars.end(),
                              [&](const std::wstring& v) {
                                  return env_name_is(v, L"PATH") || env_name_is(v, no_cwd);
                              }),
               vars.end());
    vars.push_back(L"Path=" + child_path(rules));
    vars.push_back(std::wstring(no_cwd) + L"=1");

    std::vector<wchar_t> out;
    for (const auto& v : vars) {
        out.insert(out.end(), v.begin(), v.end());
        out.push_back(L'\0');
    }
    out.push_back(L'\0');
    return out;
}

// Start `app` with `cmdline`, capturing stdout+stderr. On success returns true
// and fills out/code; if the process couldn't be started returns false and
// sets err.
bool win_launch(const PathRules& rules, const std::wstring& app, const std::wstring& cmdline, const std::wstring& cwd,
                std::string& out, int& code, DWORD& err) {
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) { err = GetLastError(); return false; }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = wr;
    si.hStdError = wr;
    PROCESS_INFORMATION pi{};

    std::vector<wchar_t> buf(cmdline.begin(), cmdline.end());
    buf.push_back(L'\0');
    std::vector<wchar_t> env = child_environment(rules);

    // `app` is an absolute path, so CreateProcess runs exactly that file and
    // searches nowhere.
    BOOL ok = CreateProcessW(app.c_str(), buf.data(), nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, env.data(),
                             cwd.empty() ? nullptr : cwd.c_str(), &si, &pi);
    if (!ok) { err = GetLastError(); CloseHandle(wr); CloseHandle(rd); return false; }
    CloseHandle(wr);

    out.clear();
    char chunk[4096];
    DWORD n = 0;
    while (ReadFile(rd, chunk, sizeof(chunk), &n, nullptr) && n > 0) out.append(chunk, n);
    CloseHandle(rd);

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD c = 0;
    GetExitCodeProcess(pi.hProcess, &c);
    code = static_cast<int>(c);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

// Run argv (no shell, unless the program is a script) and capture
// stdout+stderr. `started` is false when it never ran -- not found, refused,
// or not startable -- and the result is then the program's error message.
std::string exec_capture(const PathRules& rules, const std::vector<std::string>& argv,
                         const fs::path& cwd, int& exit_code,
                         bool& started) {
    exit_code = -1;
    started = false;
    Program prog;
    std::string error;
    if (!find_program(rules, argv[0], cwd, prog, error)) return error;
    const std::string path = prog.path.u8string();

    std::string rest;
    for (size_t i = 1; i < argv.size(); ++i) rest += ' ' + win_quote_arg(argv[i]);

    std::wstring app, cmdline;
    if (!prog.script) {
        app = prog.path.wstring();
        cmdline = utf8_to_wide(win_quote_arg(path) + rest);
    } else {
        // A .bat/.cmd only runs under cmd.exe, which re-parses the line. It
        // has no \" escape, so a quote inside a value toggles its quoting
        // and whatever follows -- `& del ...` -- becomes live syntax, and
        // %VAR% is expanded even inside quotes. No quoting makes arbitrary
        // text safe for cmd.exe, so values holding its metacharacters are
        // refused rather than silently handing the model a shell. /d skips
        // the AutoRun commands in the registry, /v:off makes `!` plain text,
        // and /s with the outer quotes runs the rest of the line verbatim.
        for (size_t i = 1; i < argv.size(); ++i) {
            if (argv[i].find_first_of("\"&|<>^%\r\n") != std::string::npos) {
                return "ERROR: '" + argv[0] + "' is a batch script that must run via "
                       "cmd.exe, and the argument '" + argv[i] + "' contains a character "
                       "(one of \" & | < > ^ % or a newline) that cmd.exe would "
                       "interpret. Use a value without those characters.";
            }
        }
        if (path.find('%') != std::string::npos) {
            return "ERROR: the script '" + path + "' has a % in its path, which cmd.exe "
                   "would expand. Move it to a folder without one.";
        }
        wchar_t sys[MAX_PATH];
        const UINT n = GetSystemDirectoryW(sys, MAX_PATH);
        if (n == 0 || n >= MAX_PATH) return "ERROR: cannot locate cmd.exe";
        app = std::wstring(sys, n) + L"\\cmd.exe";
        cmdline = L"\"" + app + L"\" /d /v:off /s /c \"" +
                  utf8_to_wide("\"" + path + "\"" + rest) + L"\"";
    }

    std::string out;
    DWORD err = 0;
    if (win_launch(rules, app, cmdline, utf8_to_wide(cwd.u8string()), out, exit_code, err)) {
        started = true;
        return out;
    }
    exit_code = -1;
    return "ERROR: failed to start '" + path + "' (CreateProcess error " +
           std::to_string(err) + ")";
}
#else
// Run argv (no shell, unless the program is a script without the execute
// bit) and capture stdout+stderr; `started` as on Windows. The child
// chdir's to `cwd` (inside the sandbox) before exec, so the parent's working
// directory is never touched.
std::string exec_capture(const PathRules& rules, const std::vector<std::string>& argv,
                         const fs::path& cwd, int& exit_code,
                         bool& started) {
    exit_code = -1;
    started = false;
    Program prog;
    std::string error;
    if (!find_program(rules, argv[0], cwd, prog, error)) return error;

    // Everything the child needs is built before fork, so it only calls
    // what is safe there.
    std::string file = prog.path.string();
    std::vector<std::string> args = argv;
    if (prog.script) {
        args.insert(args.begin(), "sh");
        args[1] = file;
        file = "/bin/sh";
    }
    std::vector<std::string> env;
    for (char** e = environ; *e; ++e) {
        if (std::strncmp(*e, "PATH=", 5) != 0) env.emplace_back(*e);
    }
    env.push_back("PATH=" + child_path(rules));
    std::vector<char*> c, e;
    for (auto& s : args) c.push_back(s.data());
    c.push_back(nullptr);
    for (auto& s : env) e.push_back(s.data());
    e.push_back(nullptr);
    const std::string dir = cwd.string();

    int fds[2];
    if (pipe(fds) != 0) return "ERROR: pipe failed";
    pid_t pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); return "ERROR: fork failed"; }
    if (pid == 0) {
        dup2(fds[1], STDOUT_FILENO);
        dup2(fds[1], STDERR_FILENO);
        close(fds[0]);
        close(fds[1]);
        if (chdir(dir.empty() ? "." : dir.c_str()) != 0) {
            const char msg[] = "ERROR: failed to change to the working directory\n";
            (void)!write(STDOUT_FILENO, msg, sizeof(msg) - 1);
            _exit(127);
        }
        execve(file.c_str(), c.data(), e.data());
        const char msg[] = "ERROR: failed to start the program\n";
        (void)!write(STDOUT_FILENO, msg, sizeof(msg) - 1);
        _exit(127);
    }
    close(fds[1]);
    started = true;
    std::string out;
    char chunk[4096];
    ssize_t n;
    while ((n = read(fds[0], chunk, sizeof(chunk))) > 0) out.append(chunk, static_cast<size_t>(n));
    close(fds[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    return out;
}
#endif

// --- built-in virtual commands --------------------------------------------
//
// A small, fixed set of read-only shell-style utilities implemented in C++ so
// they behave identically on every platform — in particular they work on pure
// Windows, where wc/head/tail/etc. are absent. They resolve paths inside the
// sandbox and never shell out. The names are reserved: run_command dispatches
// to these before consulting the user allow-list.

constexpr size_t kBuiltinMaxBytes = 64000;

// Real content lines come from tapto::content_lines (tapto/fstools.h): `view`,
// `wc -l` and the library's read_file must count a file the same way, which a
// copy of the function here would leave to chance.

std::string cap_output(std::string s) {
    if (s.size() > kBuiltinMaxBytes)
        s = s.substr(0, kBuiltinMaxBytes) + "\n... [output truncated]";
    return s;
}

std::string builtin_wc(const PathRules& rules, const std::vector<std::string>& args, const fs::path& base) {
    bool l = false, w = false, c = false;
    std::string file;
    for (const auto& a : args) {
        if (a == "-l") l = true;
        else if (a == "-w") w = true;
        else if (a == "-c") c = true;
        else if (!a.empty() && a[0] == '-') return "ERROR: wc: unknown flag '" + a + "' (use -l, -w, -c)";
        else if (file.empty()) file = a;
        else return "ERROR: wc: only one file is supported";
    }
    if (file.empty()) return "ERROR: wc: missing file operand";
    fs::path p;
    std::string err;
    if (!rules.resolve(file, p, err, base)) return err;
    std::string content;
    if (!read_file(p, content)) return "ERROR: wc: cannot read " + file;

    // Unlike POSIX wc, a last line without a trailing newline counts as a
    // line: the model uses this number to aim `view` ranges, and a file ending
    // in a bare "}" would otherwise look one line shorter than `view` shows.
    size_t lines = content_lines(content).size(), words = 0, bytes = content.size();
    bool in_word = false;
    for (char ch : content) {
        bool sp = (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\f' || ch == '\v');
        if (!sp && !in_word) { in_word = true; ++words; }
        else if (sp) in_word = false;
    }

    bool none = !l && !w && !c;
    std::ostringstream out;
    if (none || l) out << lines << " ";
    if (none || w) out << words << " ";
    if (none || c) out << bytes << " ";
    out << file;
    return out.str();
}

// Parse the leading count for head/tail from "-n N", "-nN", or "-N".
// Returns "" on success (filling n/file), or an error string.
std::string parse_head_tail(const std::vector<std::string>& args, size_t& n, std::string& file) {
    n = 10;
    for (size_t i = 0; i < args.size(); ++i) {
        const std::string& a = args[i];
        auto to_count = [&](const std::string& digits) -> bool {
            try { long v = std::stol(digits); n = v < 0 ? 0 : static_cast<size_t>(v); return true; }
            catch (const std::exception&) { return false; }
        };
        if (a == "-n") {
            if (i + 1 >= args.size()) return "ERROR: -n requires a number";
            if (!to_count(args[++i])) return "ERROR: -n: invalid number '" + args[i] + "'";
        } else if (a.rfind("-n", 0) == 0 && a.size() > 2) {
            if (!to_count(a.substr(2))) return "ERROR: -n: invalid number in '" + a + "'";
        } else if (a.size() > 1 && a[0] == '-' && std::isdigit(static_cast<unsigned char>(a[1]))) {
            if (!to_count(a.substr(1))) return "ERROR: invalid count '" + a + "'";
        } else if (!a.empty() && a[0] == '-') {
            return "ERROR: unknown flag '" + a + "' (use -n N)";
        } else if (file.empty()) {
            file = a;
        } else {
            return "ERROR: only one file is supported";
        }
    }
    if (file.empty()) return "ERROR: missing file operand";
    return "";
}

std::string builtin_head_tail(const PathRules& rules, bool head, const std::vector<std::string>& args, const fs::path& base) {
    size_t n = 10;
    std::string file;
    std::string perr = parse_head_tail(args, n, file);
    if (!perr.empty()) return perr + (head ? " (head)" : " (tail)");
    fs::path p;
    std::string err;
    if (!rules.resolve(file, p, err, base)) return err;
    std::string content;
    if (!read_file(p, content)) return "ERROR: cannot read " + file;
    // A binary file has no meaningful lines: dumping raw bytes into the result
    // would put NULs and invalid UTF-8 into the model's context and the chat
    // transcript. Refuse the same way read_file does, rather than stream it.
    if (tapto::looks_binary(content))
        return "ERROR: " + file + " is a binary file (" + std::to_string(content.size()) +
               " bytes); " + (head ? "head" : "tail") + " shows no text.";

    auto lines = content_lines(content);
    std::ostringstream out;
    if (head) {
        for (size_t i = 0; i < lines.size() && i < n; ++i) out << lines[i] << "\n";
    } else {
        size_t start = lines.size() > n ? lines.size() - n : 0;
        for (size_t i = start; i < lines.size(); ++i) out << lines[i] << "\n";
    }
    return cap_output(out.str());
}

std::string builtin_cat(const PathRules& rules, const std::vector<std::string>& args, const fs::path& base) {
    std::string file;
    for (const auto& a : args) {
        if (!a.empty() && a[0] == '-') return "ERROR: cat: unknown flag '" + a + "'";
        else if (file.empty()) file = a;
        else return "ERROR: cat: only one file is supported";
    }
    if (file.empty()) return "ERROR: cat: missing file operand";
    fs::path p;
    std::string err;
    if (!rules.resolve(file, p, err, base)) return err;
    std::error_code ec;
    if (fs::is_directory(p, ec)) return "ERROR: cat: " + file + " is a directory";
    std::string content;
    if (!read_file(p, content)) return "ERROR: cat: cannot read " + file;
    // Binary files have no text to print; refuse the same way read_file does,
    // so raw bytes never reach the model's context or the chat transcript.
    if (tapto::looks_binary(content))
        return "ERROR: cat: " + file + " is a binary file (" + std::to_string(content.size()) +
               " bytes); it has no text to show.";
    if (content.size() > kBuiltinMaxBytes)
        content = content.substr(0, kBuiltinMaxBytes) +
                  "\n... [truncated; use the editor 'view' command with view_range for more]";
    return content;
}

std::string builtin_ls(const PathRules& rules, const std::vector<std::string>& args, const fs::path& base) {
    std::string path = ".";
    bool have_path = false;
    for (const auto& a : args) {
        if (!a.empty() && a[0] == '-') return "ERROR: ls: unknown flag '" + a + "'";
        else if (!have_path) { path = a; have_path = true; }
        else return "ERROR: ls: only one path is supported";
    }
    fs::path p;
    std::string err;
    if (!rules.resolve(path, p, err, base)) return err;
    std::error_code ec;
    if (!fs::exists(p, ec)) return "ERROR: ls: path not found: " + path;
    if (!fs::is_directory(p, ec)) return p.filename().string() + "\n"; // a plain file

    std::vector<std::string> entries;
    for (const auto& e : fs::directory_iterator(p, ec)) {
        std::string name = e.path().filename().string();
        if (e.is_directory(ec)) name += "/";
        entries.push_back(name);
    }
    std::sort(entries.begin(), entries.end());
    std::ostringstream out;
    for (const auto& name : entries) out << name << "\n";
    return cap_output(out.str());
}

// Box-drawing connectors for tree output.
constexpr const char* kTreeTee = "\xe2\x94\x9c\xe2\x94\x80\xe2\x94\x80 "; // "├── "
constexpr const char* kTreeEnd = "\xe2\x94\x94\xe2\x94\x80\xe2\x94\x80 "; // "└── "
constexpr const char* kTreeBar = "\xe2\x94\x82   ";                       // "│   "
constexpr const char* kTreeGap = "    ";

void tree_walk(const fs::path& dir, const std::string& prefix, int depth_left,
               size_t& count, size_t max_count, std::ostream& out, bool& truncated) {
    std::error_code ec;
    std::vector<fs::directory_entry> entries;
    for (const auto& e : fs::directory_iterator(dir, fs::directory_options::skip_permission_denied, ec))
        entries.push_back(e);
    std::sort(entries.begin(), entries.end(),
              [](const fs::directory_entry& a, const fs::directory_entry& b) {
                  return a.path().filename().string() < b.path().filename().string();
              });

    for (size_t i = 0; i < entries.size(); ++i) {
        if (count >= max_count) { truncated = true; return; }
        const auto& e = entries[i];
        std::error_code dec;
        bool is_dir = e.is_directory(dec);
        std::string name = e.path().filename().string();
        bool last = (i + 1 == entries.size());
        out << prefix << (last ? kTreeEnd : kTreeTee) << name << (is_dir ? "/" : "") << "\n";
        ++count;
        if (is_dir && !is_noise_dir(name) && depth_left > 1) {
            tree_walk(e.path(), prefix + (last ? kTreeGap : kTreeBar),
                      depth_left - 1, count, max_count, out, truncated);
            if (truncated) return;
        }
    }
}

std::string builtin_tree(const PathRules& rules, const std::vector<std::string>& args, const fs::path& base) {
    std::string path;
    bool have_path = false;
    int depth = 1000000; // effectively unlimited unless -L is given
    for (size_t i = 0; i < args.size(); ++i) {
        const std::string& a = args[i];
        auto to_depth = [&](const std::string& digits) -> bool {
            try { int v = std::stoi(digits); depth = v < 1 ? 1 : v; return true; }
            catch (const std::exception&) { return false; }
        };
        if (a == "-L") {
            if (i + 1 >= args.size()) return "ERROR: tree: -L requires a number";
            if (!to_depth(args[++i])) return "ERROR: tree: invalid -L value '" + args[i] + "'";
        } else if (a.rfind("-L", 0) == 0 && a.size() > 2) {
            if (!to_depth(a.substr(2))) return "ERROR: tree: invalid -L value in '" + a + "'";
        } else if (!a.empty() && a[0] == '-') {
            return "ERROR: tree: unknown flag '" + a + "' (use -L depth)";
        } else if (!have_path) {
            path = a; have_path = true;
        } else {
            return "ERROR: tree: only one path is supported";
        }
    }
    if (!have_path) path = ".";
    fs::path p;
    std::string err;
    if (!rules.resolve(path, p, err, base)) return err;
    std::error_code ec;
    if (!fs::exists(p, ec)) return "ERROR: tree: path not found: " + path;
    if (!fs::is_directory(p, ec)) return path + "\n";

    constexpr size_t kMaxTreeEntries = 300;
    std::ostringstream out;
    out << path << "\n";
    size_t count = 0;
    bool truncated = false;
    tree_walk(p, "", depth, count, kMaxTreeEntries, out, truncated);
    if (truncated)
        out << "... [truncated at " << kMaxTreeEntries
            << " entries; narrow with a path or -L depth]\n";
    return cap_output(out.str());
}

// Built-in commands take a relative-to-base path: their target is resolved
// against `base` (the command's `cwd`) and pinned to the sandbox, so `ls`/`cat`/
// `tree` honour `cwd` the same way the allow-listed commands do, and can also
// take a full/relative-from-root path directly.
std::string run_builtin_command(const PathRules& rules, const std::string& name, const std::vector<std::string>& args,
                                const fs::path& base) {
    if (name == "wc")   return builtin_wc(rules, args, base);
    if (name == "head") return builtin_head_tail(rules, true, args, base);
    if (name == "tail") return builtin_head_tail(rules, false, args, base);
    if (name == "cat")  return builtin_cat(rules, args, base);
    if (name == "ls")   return builtin_ls(rules, args, base);
    if (name == "tree") return builtin_tree(rules, args, base);
    return "ERROR: unknown built-in command '" + name + "'";
}

std::string execute_list_commands(Context& /*context*/, const json& /*in*/) {
    std::ostringstream out;
    out << "Built-in commands (always available, cross-platform):\n"
           "- wc [-l|-w|-c] <file>: count lines/words/bytes\n"
           "- head [-n N] <file>: first N lines (default 10)\n"
           "- tail [-n N] <file>: last N lines (default 10)\n"
           "- cat <file>: print a file's contents\n"
           "- ls [path]: list a directory\n"
           "- tree [path] [-L depth]: show a directory tree\n";

    auto cmds = merged_commands();
    if (cmds.empty()) {
        out << (policy_allows_user_commands()
                    ? "\nNo user commands are configured. The user can add them with: "
                      "tapto-code command add <name> <command...>\n"
                    : "\nNo commands are allow-listed: the organization's policy defines "
                      "none and allows no user commands.\n");
    } else {
        out << "\nAllow-listed commands (those marked [ro] only read, so they may also "
               "run in, and take paths from, folders granted read-only). A trailing "
               "# after a command line is a note: instructions to you about how to use "
               "that command, not part of what is run:\n";
        for (const auto& [name, cmdline] : cmds) {
            const bool ro = command_reads_only(cmdline);
            out << "- " << name << ": " << (ro ? std::string(kReadOnlyMark) + " " : "")
                << command_template(cmdline);
            if (std::string note = command_note(cmdline); !note.empty())
                out << "  # " << note;
            out << "\n";
        }
    }
    return out.str();
}

std::string execute_run_command(const PathRules& rules, const json& in) {
    try {
        if (!in.contains("name")) return "ERROR: 'name' not present.";
        std::string name = in["name"].get<std::string>();

        std::vector<std::string> args;
        if (in.contains("args")) {
            if (!in["args"].is_array()) return "ERROR: 'args' must be an array of strings.";
            for (const auto& a : in["args"]) {
                args.push_back(a.is_string() ? a.get<std::string>() : a.dump());
            }
        } else if (in.contains("path") && in["path"].is_string()) {
            // Graceful fallback: the model sometimes passes the target as a
            // top-level `path` (confusing run_command with the text editor,
            // which uses `path`). Treat it as the sole argument.
            args.push_back(in["path"].get<std::string>());
        }

        // Base directory for the command (default: the working directory).
        // Resolved relative to it and confined to the folders, so a build can be pointed
        // at any subfolder — but never out of the tree. This is shared by BOTH
        // the built-ins (they resolve their relative path against it) and the
        // allow-listed commands (they run with it as their working dir), so a
        // `cwd` means the same thing in either case. What "the tree" includes
        // differs: a built-in only reads, and a command marked [ro] says it
        // only reads, so any granted folder will do; another command may do
        // anything, so only one granted read-write.
        const bool builtin = is_builtin_command(name);
        const auto cmds = merged_commands();
        const auto it = cmds.find(name);
        if (!builtin && it == cmds.end()) {
            std::string msg = "ERROR: Unknown command '" + name +
                              "'. Use list_commands to see what is available. Configured:";
            if (cmds.empty()) msg += " (none)";
            for (const auto& [n, c] : cmds) msg += " " + n;
            return msg;
        }
        const bool reads_only = builtin || command_reads_only(it->second);
        fs::path base = rules.root();
        if (base.empty() && !in.contains("cwd")) {
            return "ERROR: " + program_name() + " has no working directory: pass 'cwd', a "
                   "granted folder as <label>/<path> or an absolute path.";
        }
        if (in.contains("cwd")) {
            if (!in["cwd"].is_string()) return "ERROR: 'cwd' must be a string.";
            const std::string raw = in["cwd"].get<std::string>();
            std::string err;
            const PathScope scope = reads_only ? PathScope::Read : PathScope::Write;
            if (!rules.resolve(raw, base, err, fs::path(), scope)) return err;
            // A built-in only reads, so it may look inside a git directory or
            // the programs' own folders. Any other command run there could
            // write whatever it likes: a [ro] one too, since its mark is a
            // promise the program cannot check. The exception is a program's
            // own read-only folders (@tmp), which hold nothing a write there
            // could turn into more access.
            const bool program_read = reads_only && rules.in_read_only_program_folder(base);
            if (!builtin && !program_read && rules.refuse_protected_write(base, raw, err)) return err;
            std::error_code ec;
            if (!fs::is_directory(base, ec)) {
                return "ERROR: cwd '" + raw + "' is not an existing directory. "
                       "Create it first (e.g. with an allow-listed build command or "
                       "str_replace create) before running a command in it.";
            }
        }

        // Built-in cross-platform commands are reserved names and take
        // precedence over the user allow-list, so they behave the same on
        // every OS (and work on pure Windows where wc/head/etc. are absent).
        // Their target path resolves against `base` (they also accept a
        // relative-from-root path directly).
        if (builtin) return overflow(run_builtin_command(rules, name, args, base), name);

        // What runs is the command line without its [ro] mark.
        const std::string tpl = command_template(it->second);

        // A command defined before shell syntax was refused (or written into a
        // store by hand) says so, rather than handing `|` to the program.
        if (std::string why = command_line_refusal(it->second); !why.empty()) {
            return "ERROR: the command '" + name + "' (" + it->second + ") cannot run: " + why +
                   ". Only the user or an administrator can change that; tell the user.";
        }

        // Every command is expanded to argv and run directly — no shell, so
        // model-supplied values are passed literally (no quoting needed). A
        // command without placeholders takes no values; build_argv refuses
        // any rather than silently dropping them.
        std::vector<std::string> argv;
        {
            std::string err;
            if (!build_argv(rules, tpl, args, base, argv, err, reads_only)) return err;
        }
        int exit_code = 0;
        bool started = false;
        const std::string display = join_argv(argv);
        std::string output = exec_capture(rules, argv, base, exit_code, started);
        // Not found, refused or not startable: an error of the program's own,
        // not output of the program.
        if (!started) return output;

        // Too long for the conversation: the head and tail, and the whole of
        // it in @tmp for the model to read as it needs (tapto/overflow.h).
        output = overflow(output, name);

        std::ostringstream r;
        if (const std::string where = rules.display(base); !where.empty() && where != ".") {
            r << "working dir: " << where << "\n";
        }
        r << "$ " << display << "\n" << output;
        if (!output.empty() && output.back() != '\n') r << "\n";
        r << "[exit code: " << exit_code << "]";
        return r.str();
    } catch (const std::exception& e) {
        return std::string("ERROR: run_command failed: ") + e.what();
    }
}

// --- Status-line labels -----------------------------------------------------
//
// What the status line shows while a tool runs (tapto/editor.cpp has the
// editor's):
//
// list_commands               -> "List commands"
//
// run_command:
//   with args                 -> "Run build arg1 arg2"
//   without args              -> "Run build"

std::string display_list_commands(const json&) {
    return "List commands";
}

std::string display_run_command(const json& input) {
    if (!input.is_object()) return "run_command";
    std::string name = input.contains("name") && input["name"].is_string()
                       ? input["name"].get<std::string>() : "?";
    std::string label = "Run " + name;
    if (input.contains("args") && input["args"].is_array()) {
        for (const auto& a : input["args"]) {
            if (a.is_string()) label += " " + a.get<std::string>();
        }
    } else if (input.contains("path") && input["path"].is_string()) {
        label += " " + input["path"].get<std::string>();
    }
    return label;
}

} // namespace

bool is_builtin_command(const std::string& name) {
    return name == "wc" || name == "head" || name == "tail" ||
           name == "cat" || name == "ls" || name == "tree";
}

std::vector<ToolSpec> command_tools(const FolderSet& folders) {
    // The script folders decide what a command runs, so no write reaches
    // them, from these tools or any other.
    static const bool protected_once = [] {
        protect_folder(machine_script_folder());
        protect_folder(user_script_folder());
        return true;
    }();
    (void)protected_once;

    std::vector<ToolSpec> tools;
    const PathRules rules(folders);

    // list_commands: lets the model discover the allow-listed commands.
    ToolSpec list_cmds;
    list_cmds.name = "list_commands";
    list_cmds.description =
        "List the commands available to run via run_command (their names and the "
        "underlying command lines). Only these pre-approved commands can be run.";
    list_cmds.parameters = {{"type", "object"}, {"properties", json::object()}};
    list_cmds.executor = execute_list_commands;
    list_cmds.display = display_list_commands;
    tools.push_back(std::move(list_cmds));

    // run_command: runs one allow-listed command by name. The model cannot
    // supply arbitrary shell text — only choose a configured command.
    ToolSpec run;
    run.name = "run_command";
    run.description =
        "Run a command by name. Two kinds are available (call list_commands to see "
        "them): (1) built-in cross-platform utilities that always work, including on "
        "Windows: wc [-l|-w|-c] <file>, head [-n N] <file>, tail [-n N] <file>, "
        "cat <file>, ls [path], tree [path] [-L depth]; and (2) the project's "
        "pre-approved commands configured via 'tapto-code command add'. Arbitrary "
        "shell commands are NOT allowed. ALL command-specific arguments (file paths, "
        "flags, values for %1/%2 placeholders) go in the 'args' array, in order — "
        "there is no separate 'path' parameter; e.g. list a directory with "
        "{\"name\":\"ls\",\"args\":[\"driver\"]} or pass a file to cat with "
        "{\"name\":\"cat\",\"args\":[\"src/main.cpp\"]}. Pass 'cwd' to run the "
        "command in a subdirectory of the working folder (e.g. to build in a "
        "subfolder); it is confined to the working directory. For the built-in "
        "commands it also sets the folder their path is resolved from, so 'ls' with "
        "args ['foo'] and cwd 'sub' lists 'sub/foo'. Returns the command's output.";
    run.parameters = {
        {"type", "object"},
        {"properties", {
            {"name", {{"type", "string"}, {"description", "Name of the built-in or configured command to run."}}},
            {"args", {
                {"type", "array"},
                {"items", {{"type", "string"}}},
                {"description", "Arguments for the command (built-in flags/paths, or values for %1, %2, ... placeholders), in order."}
            }},
            {"cwd", {
                {"type", "string"},
                {"description", "Optional directory to run the command in, relative to (or absolute within) the working directory. Must exist and stay inside the working directory. Use to build in subfolders, or as the folder a built-in command's relative path is resolved from. Defaults to the working directory."}
            }},
        }},
        {"required", {"name"}},
    };
    run.executor = [rules](Context&, const json& in) { return execute_run_command(rules, in); };
    run.display = display_run_command;
    tools.push_back(std::move(run));

    return tools;
}

} // namespace tapto

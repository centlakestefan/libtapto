// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#include "tapto/pathrules.h"

#include "tapto/config.h"
#include "tapto/paths.h"
#include "tapto/program.h"

#include <cctype>
#include <cstring>
#include <cwctype>
#include <mutex>
#include <vector>

namespace fs = std::filesystem;

namespace tapto {

namespace {

// True if `path` is `root` or under it, both already canonical.
bool is_under(const fs::path& root, const fs::path& path) {
    if (root.empty()) return false;
    const fs::path rel = path.lexically_relative(root);
    return !rel.empty() && *rel.begin() != fs::path("..");
}

// One path component compared the way the filesystem would: Windows is
// case-insensitive, so ".GIT" names the same directory as ".git" there.
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

// True if any component of `path` is named ".git".
bool has_git_component(const fs::path& path) {
    for (const auto& part : path) {
        if (component_is(part, ".git")) return true;
    }
    return false;
}

// True if `dir` is a git directory judged by what it holds rather than by its
// name: HEAD beside objects/ and refs/ is the layout git itself looks for.
// This is what catches a repository whose git directory is not called ".git"
// -- `git init --separate-git-dir`, a linked worktree, or a bare repo planted
// in the tree -- where the name-based check has nothing to match.
bool looks_like_git_dir(const fs::path& dir) {
    std::error_code ec;
    return fs::exists(dir / "HEAD", ec) && fs::is_directory(dir / "objects", ec) &&
           fs::is_directory(dir / "refs", ec);
}

// A path made canonical where it exists and tidied where it doesn't, so two
// spellings of one folder compare equal.
fs::path canonical_or_normal(const fs::path& p) {
    std::error_code ec;
    fs::path c = fs::weakly_canonical(p, ec);
    return ec ? p.lexically_normal() : c;
}

// is_under with the filesystem's idea of case: on Windows a folder that does
// not exist yet keeps the case it was written in, so ".TAPTO\commands" has to
// match "...\.tapto" by name.
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

std::string& read_only_advice() {
    static std::string advice =
        "Reading it is fine; to change it, ask the user to grant the folder read-write "
        "with /add-folder <path> rw.";
    return advice;
}

std::mutex& protected_mutex() {
    static std::mutex m;
    return m;
}
std::vector<fs::path>& protected_extra() {
    static std::vector<fs::path> dirs;
    return dirs;
}

// The folders the tapto programs keep their own state in: ~/.tapto (the global
// store, every project's local store and command list, saved conversations),
// the machine-wide store, and what a program protects besides. None of it is
// the model's to change, and a writable command store is a way to run
// anything: the agent adds a command and runs it. That matters as soon as the
// working directory contains them, which is what starting a program in the
// home folder (or at the root of a drive) does.
std::vector<fs::path> tapto_dirs() {
    std::vector<fs::path> dirs;
    for (const fs::path& d : {global_dir(), config_path(Level::System).parent_path()}) {
        if (!d.empty()) dirs.push_back(canonical_or_normal(d));
    }
    std::lock_guard<std::mutex> lock(protected_mutex());
    for (const fs::path& d : protected_extra()) dirs.push_back(d);
    return dirs;
}

} // namespace

void set_read_only_advice(const std::string& advice) {
    std::lock_guard<std::mutex> lock(protected_mutex());
    if (!advice.empty()) read_only_advice() = advice;
}

void protect_folder(const fs::path& dir) {
    if (dir.empty()) return;
    const fs::path c = canonical_or_normal(dir);
    std::lock_guard<std::mutex> lock(protected_mutex());
    for (const fs::path& have : protected_extra()) {
        if (have == c) return;
    }
    protected_extra().push_back(c);
}

fs::path PathRules::root() const {
    const Folder* h = m_folders.home();
    return h ? h->root : fs::path();
}

const Folder* PathRules::owner(const fs::path& resolved, bool writable_only) const {
    const Folder* f = m_folders.owner(resolved);
    return f && (f->writable || !writable_only) ? f : nullptr;
}

bool PathRules::in_read_only_program_folder(const fs::path& resolved) const {
    const Folder* f = owner(resolved, /*writable_only=*/false);
    return f && f->system && !f->writable;
}

// A granted folder is reached either as "<label>/<rest>" or as an absolute
// path under its root. The label form is taken only when resolving from the
// working directory itself and it has no entry of that name, so a project's
// own subfolder always wins over a grant that happens to share its name; the
// absolute form is always unambiguous. The set's home root is the working
// directory under its own label, so "<label>/<rest>" as the folder tools
// print it comes back here and lands where it came from. A program's own '@'
// labels are never shadowed by a project entry. Without a working directory
// a path is a label's or absolute.
bool PathRules::resolve(const std::string& input, fs::path& out, std::string& error,
                        const fs::path& base, PathScope scope) const {
    const fs::path root = this->root();
    const fs::path anchor = base.empty() ? root : base;
    const bool grants = scope != PathScope::WorkingDir;
    const bool writes = scope == PathScope::Write;
    std::error_code ec;
    fs::path in_path(input);

    auto refuse_read_only = [&](const Folder& f) {
        if (f.system) {
            error = "ERROR: '" + input + "' is in " + f.label + ", " + program_name() +
                    "'s own folder (" + f.note + "). It can be read, not changed.";
            return false;
        }
        std::lock_guard<std::mutex> lock(protected_mutex());
        error = "ERROR: '" + input + "' is in '" + f.label + "', which the user granted "
                "read-only. " + read_only_advice();
        return false;
    };

    if (grants && !in_path.is_absolute() && !in_path.empty() && anchor == root) {
        const std::string head = in_path.begin()->string();
        const Folder* f = m_folders.get(head);
        // A grant's label gives way to a project entry of the same name; a
        // program's own '@' labels never do.
        if (f && (f->system || root.empty() || !fs::exists(anchor / head, ec))) {
            if (writes && !f->writable) return refuse_read_only(*f);
            fs::path rest;
            for (auto it = std::next(in_path.begin()); it != in_path.end(); ++it) rest /= *it;
            fs::path abs = f->root / rest;
            fs::path resolved = fs::weakly_canonical(abs, ec);
            if (ec) resolved = abs.lexically_normal();
            if (resolved == f->root || is_under(f->root, resolved)) {
                out = resolved;
                return true;
            }
        }
    }

    // Without a working directory a relative path has nothing to be relative
    // to: it was a label's, and no folder has that label.
    if (!in_path.is_absolute() && anchor.empty()) {
        error = "ERROR: '" + input + "' names no folder " + program_name() + " can reach. " +
                (m_folders.empty() ? std::string("The user has granted none; they grant one "
                                                 "with /add-folder <path>.")
                                   : std::string("Write it as <label>/<path>, with a label "
                                                 "from list_folders, or as an absolute path."));
        return false;
    }

    fs::path abs = in_path.is_absolute() ? in_path : (anchor / in_path);
    fs::path resolved = fs::weakly_canonical(abs, ec);
    if (ec) resolved = abs.lexically_normal();

    if (resolved == root || is_under(root, resolved)) {
        out = resolved;
        return true;
    }
    if (grants) {
        if (const Folder* f = owner(resolved, /*writable_only=*/false)) {
            if (writes && !f->writable) return refuse_read_only(*f);
            out = resolved;
            return true;
        }
    }
    if (root.empty()) {
        error = "ERROR: '" + input + "' is outside the folders " + program_name() +
                " can reach: the ones the user granted" +
                (writes ? std::string(" read-write.") : std::string("."));
        return false;
    }
    error = "ERROR: '" + input + "' is outside the working directory. " + program_name() +
            " can only access the folder it was started in and its subdirectories" +
            std::string(grants && m_folders.has_grants()
                            ? (writes ? ", plus any folder the user has granted read-write."
                                      : ", plus any folder the user has granted.")
                            : ".");
    return false;
}

// True if writing to `resolved` would land in a repository's git directory.
// The model has no reason to write there, and a writable git directory turns
// every git command into code execution: config can name a core.fsmonitor or
// core.hooksPath command that even `git status` runs, and hooks/* run on
// commit. Checked against whichever root the path landed in, so a writable
// grant is covered too.
//
// Three ways in, because one name test isn't enough:
//   the resolved path    the ordinary case, ".git/hooks/pre-commit";
//   `input` as written   paths are canonicalized before they get here, so a
//                        symlinked .git would otherwise resolve to a target
//                        with no ".git" component left to match;
//   an ancestor's shape  a git directory under any other name (above).
static bool in_git_dir(const PathRules& rules, const fs::path& resolved, const std::string& input) {
    const Folder* f = rules.owner(resolved, /*writable_only=*/true);
    const fs::path root = f ? f->root : rules.root();

    if (!root.empty() && has_git_component(resolved.lexically_relative(root))) return true;
    if (has_git_component(fs::path(input).lexically_normal())) return true;

    // Up from the target to the root it landed in, the root included: a bare
    // repository can sit at the top of the tree. The target itself is the
    // starting point when it is a directory, which is what a command's `cwd`
    // is.
    std::error_code ec;
    fs::path start = fs::is_directory(resolved, ec) ? resolved : resolved.parent_path();
    for (fs::path dir = start; dir == root || is_under(root, dir); dir = dir.parent_path()) {
        if (looks_like_git_dir(dir)) return true;
        if (dir == root || dir == dir.parent_path()) break;
    }
    return false;
}

// True if writing to `resolved` would land in one of tapto_dirs(), or in any
// folder named ".tapto". As with the git directory, the path is checked as
// resolved and as written: a symlink or junction to ~/.tapto resolves to a
// path with no ".tapto" left in its relative part, which the canonical
// comparison catches, while a ".tapto" that does not exist yet is caught by
// its name.
static bool in_tapto_dir(const PathRules& rules, const fs::path& resolved,
                         const std::string& input) {
    const Folder* f = rules.owner(resolved, /*writable_only=*/true);
    const fs::path root = f ? f->root : rules.root();
    if (!root.empty()) {
        for (const auto& part : resolved.lexically_relative(root)) {
            if (component_is(part, ".tapto")) return true;
        }
    }
    for (const auto& part : fs::path(input).lexically_normal()) {
        if (component_is(part, ".tapto")) return true;
    }
    for (const fs::path& dir : tapto_dirs()) {
        if (dir == resolved || is_within(dir, resolved)) return true;
    }
    return false;
}

// A program's own writable folder (@memory) sits in ~/.tapto and is refused
// here like the rest of it: the editor's exception lives in resolve_for_editor
// alone, so a program's other tools never reach it, not even through a
// writable grant that covers the home folder.
bool PathRules::refuse_protected_write(const fs::path& resolved, const std::string& input,
                                       std::string& error) const {
    if (in_git_dir(*this, resolved, input)) {
        error = "ERROR: '" + input + "' is inside a repository's git directory, which " +
                program_name() + " never writes to. Use an allow-listed git command instead.";
        return true;
    }
    if (in_tapto_dir(*this, resolved, input)) {
        error = "ERROR: '" + input + "' is inside " + program_name() +
                "'s own folders (its settings, allow-listed commands and scripts), which " +
                program_name() + " never writes to. Only the user can change them.";
        return true;
    }
    return false;
}

bool PathRules::resolve_for_read(const std::string& input, fs::path& out,
                                 std::string& error) const {
    return resolve(input, out, error);
}

bool PathRules::resolve_for_editor(const std::string& input, fs::path& out,
                                   std::string& error) const {
    if (!resolve(input, out, error, fs::path(), PathScope::Write)) return false;
    if (const Folder* f = owner(out, /*writable_only=*/true); f && f->system) return true;
    return !refuse_protected_write(out, input, error);
}

bool PathRules::resolve_plugin_path(const std::string& input, bool write, fs::path& out,
                                    std::string& display, std::string& error) const {
    if (write) {
        // A program's own write rules: rw grants, and refuse_protected_write
        // without the editor's @memory exception.
        if (!resolve(input, out, error, fs::path(), PathScope::Write)) return false;
        if (refuse_protected_write(out, input, error)) return false;
    } else if (!resolve_for_read(input, out, error)) {
        return false;
    }
    display = input;
    const fs::path root = this->root();
    if (!(out == root || is_under(root, out)) && m_folders.owner(out))
        display = m_folders.display(out);
    return true;
}

std::string PathRules::display(const fs::path& p) const {
    const fs::path root = this->root();
    if (!root.empty() && (p == root || is_under(root, p)))
        return p.lexically_relative(root).generic_string();
    return m_folders.display(p);
}

} // namespace tapto

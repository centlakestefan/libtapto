// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#pragma once

#include <filesystem>
#include <string>

#include "tapto/fstools.h"

namespace tapto {

// ---------------------------------------------------------------------------
// Where a path the model names may lead, for every tool that takes one: the
// editor (tapto/editor.h), a plugin's path arguments, and a program's own
// tools (tapto-code's commands).
//
// The rules are a FolderSet's. Its home root (FolderSet::set_home) is the
// working directory, reached by a relative path; a program without one
// (tapto-word) reaches only the folders in the set, by "<label>/<path>" or an
// absolute path. A granted folder is reached by its label or by an absolute
// path under it; a program's own folders ('@' labels) the same way, by their
// mode.
//
// Writes are refused in a repository's git directory, whatever the grant (a
// writable one runs code: core.fsmonitor, hooks), and in the tapto programs'
// own folders: ~/.tapto, the machine-wide store, and what a program adds
// with protect_folder() (tapto-code's command scripts). The editor alone may
// write in a program's own writable folder (@memory), which is in ~/.tapto.
// ---------------------------------------------------------------------------

// What a path may reach beyond the working directory, which every scope has.
//
//   Read        every folder in the set, read-only ones included: a read is
//               a read whichever tool the model picks.
//   Write       the folders marked rw: the editor's create and edit, and
//               whatever a program lets write (tapto-code: a command's cwd
//               and %p paths).
//   WorkingDir  the working directory alone.
enum class PathScope { Read, Write, WorkingDir };

// One more folder no write may touch, beside ~/.tapto and the machine-wide
// store: a program's own state kept elsewhere. For every PathRules.
void protect_folder(const std::filesystem::path& dir);

// What a refusal to write in a read-only grant goes on to say, after "...
// which the user granted read-only.": by default that reading is fine and
// how to ask for read-write. A program with more ways to read there says so
// (tapto-code: its [ro] commands). For every PathRules.
void set_read_only_advice(const std::string& advice);

class PathRules {
public:
    // The set must outlive this object, and may change after it is made: it
    // is consulted on every resolution, so a grant made mid-session is seen.
    explicit PathRules(const FolderSet& folders) : m_folders(folders) {}

    // The working directory (the set's home root), or an empty path for a
    // program without one.
    std::filesystem::path root() const;

    // Resolves `input` (absolute, "<label>/<rest>", or relative to `base`,
    // which defaults to the working directory) within `scope`. On success
    // `out` is the resolved absolute path; else `error` is the tool result
    // to return ("ERROR: ..."). ".." and symlinks in the existing prefix are
    // resolved first, so neither escapes.
    bool resolve(const std::string& input, std::filesystem::path& out, std::string& error,
                 const std::filesystem::path& base = {}, PathScope scope = PathScope::Read) const;

    // True (and `error`) when a write must not touch `resolved`: a git
    // directory or the tapto programs' own folders.
    bool refuse_protected_write(const std::filesystem::path& resolved, const std::string& input,
                                std::string& error) const;

    // What the editor reads: every folder in the set, no protected refusal
    // (the model may look into .git and ~/.tapto).
    bool resolve_for_read(const std::string& input, std::filesystem::path& out,
                          std::string& error) const;
    // What the editor writes: Write scope and the protected refusal, except
    // in a program's own writable folder (@memory), which only the editor
    // writes. The one place that exception is made.
    bool resolve_for_editor(const std::string& input, std::filesystem::path& out,
                            std::string& error) const;

    // A plugin tool's path argument ("x-tapto-path"). `write` false reads as
    // the editor reads; true writes as a program's own tools do: rw grants,
    // the protected refusal, and not @memory. `display` is the path as tool
    // results print it ("<label>/<rest>" in a folder of the set, else the
    // model's own spelling).
    bool resolve_plugin_path(const std::string& input, bool write, std::filesystem::path& out,
                             std::string& display, std::string& error) const;

    // The folder of the set that holds `resolved` (the deepest), or null;
    // `writable_only` narrows it to rw ones.
    const Folder* owner(const std::filesystem::path& resolved, bool writable_only) const;

    // True when `resolved` is in one of the program's own folders the model
    // may only read (@tmp): a program may let a tool that only reads go
    // there although it is in ~/.tapto.
    bool in_read_only_program_folder(const std::filesystem::path& resolved) const;

    // `p` as the model should see it: relative to the working directory, or
    // "<label>/<rest>" in another folder of the set.
    std::string display(const std::filesystem::path& p) const;

    const FolderSet& folders() const { return m_folders; }

private:
    const FolderSet& m_folders;
};

} // namespace tapto

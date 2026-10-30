// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#pragma once

#include <filesystem>

namespace tapto {

// Config scopes, ordered lowest to highest precedence.
//
// The first three are the user's: files the programs read and write. Policy
// is the organization's and read-only: what an administrator mandates through
// Group Policy (the registry, on Windows) or a root-owned file (elsewhere),
// applied last so it overrides whatever the user wrote. See tapto/policy.h.
enum class Level { System, Global, Local, Policy };

// Human-readable name ("system" / "global" / "local" / "policy").
const char* level_name(Level level);

// The project folder: the one the local scope belongs to, and what a relative
// folder the user names (/add-folder) is relative to. The process's working
// directory unless the program names another: a program loaded into someone
// else's process (an IDE extension in devenv.exe) cannot change that
// directory, and its project can change while it runs. An empty path goes back
// to the working directory. Safe to call from any thread.
void set_project_dir(const std::filesystem::path& dir);
std::filesystem::path project_dir();

// Resolve the config file path for a scope.
//
// System and Global are fixed per-machine / per-user. Local (project) scope is
// stored centrally per project folder (project_dir()) under the user's home
// (~/.tapto/projects/<encoded-cwd>/config), NOT inside the project folder —
// so a cloned repo can't ship config/commands and nothing is written into the
// project tree. No upward search.
//
// Policy is a file only where there is no registry: /etc/tapto/policy. On
// Windows it comes from the registry and this returns an empty path; use
// policy_entries() from tapto/policy.h to read it on every platform.
std::filesystem::path config_path(Level level);

// Same resolution as config_path, but for the allow-listed commands store: the
// "commands" file beside that scope's "config", so the local one is
// ~/.tapto/projects/<encoded-cwd>/commands and never sits in the project.
// Policy: /etc/tapto/policy-commands, or empty on Windows where the list is
// the registry's `commands` subkey (policy_commands()).
std::filesystem::path commands_path(Level level);

// The per-user tapto directory (~/.tapto), home of the global store and of
// anything else that belongs to the user rather than to a project: the
// certificates the sidecars serve, for one.
std::filesystem::path global_dir();

} // namespace tapto

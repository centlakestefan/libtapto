// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#include "tapto/paths.h"

#include <cstdlib>
#include <mutex>
#include <system_error>

namespace fs = std::filesystem;

namespace tapto {

namespace {

fs::path env_path(const char* name) {
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4996) // std::getenv is the portable, intended call here
#endif
    const char* value = std::getenv(name);
#ifdef _MSC_VER
#pragma warning(pop)
#endif
    return value ? fs::path(value) : fs::path();
}

fs::path system_store_path(const std::string& filename) {
#ifdef _WIN32
    fs::path base = env_path("PROGRAMDATA");
    if (base.empty()) base = "C:\\ProgramData";
    return base / "tapto" / filename;
#else
    return fs::path("/etc/tapto") / filename;
#endif
}

fs::path home_dir() {
#ifdef _WIN32
    fs::path home = env_path("USERPROFILE");
    if (home.empty()) home = env_path("HOMEDRIVE") / env_path("HOMEPATH");
#else
    fs::path home = env_path("HOME");
#endif
    return home;
}

fs::path global_store_path(const std::string& filename) {
    return home_dir() / ".tapto" / filename;
}

// Encode an absolute directory path into a single filename-safe key.
std::string project_key(const fs::path& dir) {
    std::string key;
    for (char c : dir.string()) {
        key += (c == '\\' || c == '/' || c == ':') ? '_' : c;
    }
    size_t start = key.find_first_not_of('_');
    key = (start == std::string::npos) ? std::string("root") : key.substr(start);
    return key;
}

fs::path canonical_or_given(const fs::path& p) {
    std::error_code ec;
    fs::path canon = fs::weakly_canonical(p, ec);
    return ec ? p : canon;
}

// The folder set_project_dir() named, empty for the working directory. The
// host may change it on its UI thread while a chat thread reads it.
std::mutex& project_mutex() {
    static std::mutex m;
    return m;
}
fs::path& project_storage() {
    static fs::path dir;
    return dir;
}

// The project (local) scope is stored centrally per project folder under the
// user's home, NOT inside the project folder. This means a cloned repo can't
// ship config/commands to the agent, and nothing is ever written into the
// project tree (so no .gitignore entry is needed). Keyed by the canonical
// absolute path of the project folder.
fs::path local_path(const std::string& filename) {
    return home_dir() / ".tapto" / "projects" / project_key(project_dir()) / filename;
}

// Resolve the path to a named store file ("config", "commands", ...) for a scope.
fs::path store_path(Level level, const std::string& filename) {
    switch (level) {
        case Level::System: return system_store_path(filename);
        case Level::Global: return global_store_path(filename);
        case Level::Local:  return local_path(filename);
        case Level::Policy: break;
    }
    return fs::path();
}

// The organization's policy files, on platforms without a registry. They sit
// next to the system store but are different files: the system store holds
// defaults the user may override, these hold what the user may not.
fs::path policy_file_path(const char* filename) {
#ifdef _WIN32
    (void)filename;
    return fs::path(); // policy comes from the registry; see tapto/policy.h
#else
    return fs::path("/etc/tapto") / filename;
#endif
}

} // namespace

const char* level_name(Level level) {
    switch (level) {
        case Level::System: return "system";
        case Level::Global: return "global";
        case Level::Local:  return "local";
        case Level::Policy: return "policy";
    }
    return "unknown";
}

void set_project_dir(const fs::path& dir) {
    fs::path canon;
    if (!dir.empty()) {
        std::error_code ec;
        canon = canonical_or_given(fs::absolute(dir, ec));
        if (ec) canon = dir;
    }
    std::lock_guard<std::mutex> lock(project_mutex());
    project_storage() = canon;
}

fs::path project_dir() {
    {
        std::lock_guard<std::mutex> lock(project_mutex());
        if (!project_storage().empty()) return project_storage();
    }
    std::error_code ec;
    fs::path cwd = fs::current_path(ec);
    if (ec) cwd = ".";
    return canonical_or_given(cwd);
}

fs::path global_dir() {
    return home_dir() / ".tapto";
}

fs::path config_path(Level level) {
    if (level == Level::Policy) return policy_file_path("policy");
    return store_path(level, "config");
}

fs::path commands_path(Level level) {
    if (level == Level::Policy) return policy_file_path("policy-commands");
    return store_path(level, "commands");
}

} // namespace tapto

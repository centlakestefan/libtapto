// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#include "tapto/program.h"

#include <iterator>
#include <system_error>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#elif defined(__APPLE__)
#  include <mach-o/dyld.h>
#endif

namespace fs = std::filesystem;

namespace tapto {

namespace {
std::string& name_storage() {
    static std::string name = "tapto";
    return name;
}
} // namespace

void set_program_name(const std::string& name) {
    if (!name.empty()) name_storage() = name;
}

const std::string& program_name() {
    return name_storage();
}

fs::path program_file() {
#ifdef _WIN32
    // The module holding this function, not the process's executable: linked
    // into a DLL that devenv.exe loads, that is the DLL. In an executable the
    // two are the same.
    HMODULE self = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(&program_file), &self)) {
        return {};
    }
    wchar_t path[MAX_PATH * 4];
    const DWORD n = GetModuleFileNameW(self, path, static_cast<DWORD>(std::size(path)));
    if (n == 0 || n >= std::size(path)) return {};
    return fs::path(path);
#elif defined(__APPLE__)
    char buf[4096];
    uint32_t size = sizeof buf;
    if (_NSGetExecutablePath(buf, &size) != 0) return {};
    std::error_code ec;
    return fs::canonical(buf, ec);
#else
    std::error_code ec;
    const fs::path exe = fs::read_symlink("/proc/self/exe", ec);
    return ec ? fs::path() : exe;
#endif
}

const std::vector<std::string>& program_names() {
    static const std::vector<std::string> names = {"tapto-code", "tapto-word", "tapto-vnc",
                                                         "tapto-msvc"};
    return names;
}

std::string split_program_key(const std::string& key, std::string* program) {
    if (program) program->clear();
    const std::size_t dot = key.find('.');
    if (dot == std::string::npos || dot + 1 == key.size()) return key;
    const std::string prefix = key.substr(0, dot);
    for (const auto& name : program_names()) {
        if (prefix != name) continue;
        if (program) *program = name;
        return key.substr(dot + 1);
    }
    return key;
}

} // namespace tapto

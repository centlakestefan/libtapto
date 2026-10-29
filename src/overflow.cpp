// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#include "tapto/overflow.h"

#include <chrono>
#include <fstream>
#include <mutex>
#include <random>
#include <set>
#include <system_error>
#include <vector>

#include "tapto/paths.h"

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#else
#  include <cerrno>
#  include <csignal>
#  include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace tapto {

namespace {

unsigned long current_pid() {
#ifdef _WIN32
    return GetCurrentProcessId();
#else
    return static_cast<unsigned long>(getpid());
#endif
}

// Whether the process `pid` is still running. A pid the system has since
// given to another process reads as running, which only keeps a stale folder
// a little longer.
bool process_running(unsigned long pid) {
#ifdef _WIN32
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (!h) return GetLastError() == ERROR_ACCESS_DENIED; // someone else's process
    DWORD code = 0;
    const bool running = GetExitCodeProcess(h, &code) && code == STILL_ACTIVE;
    CloseHandle(h);
    return running;
#else
    return kill(static_cast<pid_t>(pid), 0) == 0 || errno == EPERM;
#endif
}

// The folders this process has open, so making one never removes another
// session's of the same process (tapto-word has one per document).
std::mutex& open_mutex() {
    static std::mutex m;
    return m;
}
std::set<fs::path>& open_folders() {
    static std::set<fs::path> s;
    return s;
}

// A file name made of the hint's letters, digits, '-' and '_' only.
std::string safe_name(const std::string& hint) {
    std::string out;
    for (char c : hint) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '-' || c == '_';
        out += ok ? c : '_';
        if (out.size() >= 32) break;
    }
    return out.empty() ? std::string("output") : out;
}

std::string random_hex(int digits) {
    static std::mutex m;
    static std::mt19937 rng{std::random_device{}()};
    static const char* const kHex = "0123456789abcdef";
    std::lock_guard<std::mutex> lock(m);
    std::string out;
    for (int i = 0; i < digits; ++i) out += kHex[rng() & 0xF];
    return out;
}

// Back from `n` to the start of a UTF-8 character, so a cut never splits one.
std::size_t char_boundary(const std::string& s, std::size_t n) {
    while (n > 0 && n < s.size() && (static_cast<unsigned char>(s[n]) & 0xC0) == 0x80) --n;
    return n;
}

} // namespace

fs::path TempFolder::open(const fs::path& parent, std::string& error) {
    close();
    if (parent.empty()) {
        error = "no project folder (the working directory could not be read)";
        return {};
    }
    std::error_code ec;
    std::lock_guard<std::mutex> lock(open_mutex());

    // Folders of sessions that are gone: named "<pid>-<time>[-<n>]", and that
    // pid no longer runs, or it is this process and the folder is not open
    // (a session before it that reused the pid).
    for (fs::directory_iterator it(parent, ec), end; !ec && it != end; it.increment(ec)) {
        const std::string name = it->path().filename().string();
        const std::size_t dash = name.find('-');
        if (dash == std::string::npos || dash == 0) continue;
        unsigned long pid = 0;
        try {
            pid = std::stoul(name.substr(0, dash));
        } catch (...) {
            continue;
        }
        if (pid == current_pid() ? open_folders().count(it->path()) > 0 : process_running(pid))
            continue;
        std::error_code rm;
        fs::remove_all(it->path(), rm);
    }

    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    const std::string base = std::to_string(current_pid()) + "-" + std::to_string(now);
    fs::path dir = parent / base;
    // Two sessions of one process started in the same second.
    for (int n = 2; fs::exists(dir, ec) || open_folders().count(dir); ++n)
        dir = parent / (base + "-" + std::to_string(n));
    ec.clear();
    fs::create_directories(dir, ec);
    if (ec) {
        error = "cannot make " + dir.string() + ": " + ec.message();
        return {};
    }
    open_folders().insert(dir);
    m_made = dir;
    return dir;
}

void TempFolder::close() {
    if (m_made.empty()) return;
    std::error_code ec;
    fs::remove_all(m_made, ec);
    {
        std::lock_guard<std::mutex> lock(open_mutex());
        open_folders().erase(m_made);
    }
    if (m_dir == m_made) m_dir.clear();
    m_made.clear();
}

void TempFolder::use(const fs::path& dir, const std::string& label) {
    m_dir = dir;
    m_label = label;
}

std::string TempFolder::overflow(const std::string& text, const std::string& name_hint) {
    if (text.size() <= kOverflowBytes) return text;

    // The lines, each with its '\n' (the last may have none).
    std::vector<std::pair<std::size_t, std::size_t>> lines; // offset, length
    for (std::size_t at = 0; at < text.size();) {
        std::size_t nl = text.find('\n', at);
        const std::size_t end = nl == std::string::npos ? text.size() : nl + 1;
        lines.emplace_back(at, end - at);
        at = end;
    }
    const std::size_t n = lines.size();

    // Whole lines from the start, then from the end, within their budgets.
    std::size_t head = 0, head_bytes = 0;
    while (head < n && head_bytes + lines[head].second <= kOverflowHeadBytes) {
        head_bytes += lines[head++].second;
    }
    std::size_t tail = 0, tail_bytes = 0;
    while (tail < n - head && tail_bytes + lines[n - 1 - tail].second <= kOverflowTailBytes) {
        tail_bytes += lines[n - 1 - tail++].second;
    }

    // Where all of it goes.
    std::string where;
    if (!m_dir.empty()) {
        const std::string file = safe_name(name_hint) + "-" + std::to_string(++m_count) +
                                 "-" + random_hex(4) + ".txt";
        std::ofstream out(m_dir / file, std::ios::binary | std::ios::trunc);
        out << text;
        out.close();
        if (out) where = m_label + "/" + file;
    }

    // No line fits (one long line, minified JSON): the start of the first.
    const bool partial = head == 0;
    std::string result = partial ? text.substr(0, char_boundary(text, kOverflowHeadBytes))
                                 : text.substr(0, head_bytes);
    if (!result.empty() && result.back() != '\n') result += "\n";

    const std::size_t first = head + 1, last = n - tail; // 1-based, inclusive
    const std::string range = first == last ? "line " + std::to_string(first)
                                            : "lines " + std::to_string(first) + "-" +
                                                  std::to_string(last);
    std::string note = "[... the output was cut: " + range + " of " + std::to_string(n) +
                       (first == last ? " is" : " are") +
                       (partial ? " not shown in full" : " not shown") + " here (" +
                       std::to_string(text.size()) + " bytes in all).";
    if (!where.empty()) {
        note += " The whole output is in " + where +
                ", read-only: view it there with view_range to read what was left out, "
                "or search it.";
    } else {
        note += " That part could not be kept; run the command again with narrower "
                "arguments.";
    }
    result += note + "]\n";
    if (tail) result += text.substr(lines[n - tail].first);
    return result;
}

std::string TempFolder::write(const std::string& data, const std::string& name_hint,
                              std::string& error) {
    if (m_dir.empty()) {
        error = "this session has no @tmp folder";
        return {};
    }
    // The hint's extension is kept, so the model (and its tools) can tell a
    // .pdf from a .txt.
    std::string stem = name_hint, ext;
    if (const std::size_t dot = name_hint.find_last_of('.');
        dot != std::string::npos && dot > 0 && dot + 1 < name_hint.size()) {
        stem = name_hint.substr(0, dot);
        ext = "." + safe_name(name_hint.substr(dot + 1)).substr(0, 8);
    }
    const std::string file = safe_name(stem) + "-" + random_hex(6) + ext;
    std::ofstream out(m_dir / file, std::ios::binary | std::ios::trunc);
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
    out.close();
    if (!out) {
        error = "cannot write " + (m_dir / file).string();
        return {};
    }
    return m_label + "/" + file;
}

TempFolder& default_temp_folder() {
    // The registry first, so it outlives the folder, whose destructor (at
    // exit, for a program that never closed it) uses it.
    open_mutex();
    open_folders();
    static TempFolder folder;
    return folder;
}

fs::path open_session_tmp(std::string& error) {
    const fs::path project = config_path(Level::Local).parent_path();
    return default_temp_folder().open(project.empty() ? fs::path() : project / "tmp", error);
}

void close_session_tmp() {
    default_temp_folder().close();
}

void set_overflow_folder(const fs::path& dir, const std::string& label) {
    default_temp_folder().use(dir, label);
}

std::string overflow(const std::string& text, const std::string& name_hint) {
    return default_temp_folder().overflow(text, name_hint);
}

std::string write_temp_file(const std::string& data, const std::string& name_hint,
                            std::string& error) {
    return default_temp_folder().write(data, name_hint, error);
}

} // namespace tapto

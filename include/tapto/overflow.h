// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#pragma once

#include <cstddef>
#include <filesystem>
#include <string>

namespace tapto {

// ---------------------------------------------------------------------------
// Tool output too long for the conversation, and files for the model to read.
//
// A tool result past kOverflowBytes is not cut and lost: the whole of it is
// written to a file in the session's own folder, and the model gets its first
// and last lines with a note between them naming the lines left out and the
// file that holds them, which it reads (or searches) as it needs. A plugin's
// file (a downloaded attachment) goes there too.
//
// The folder is the session's, under the project's state beside its config:
//
//   ~/.tapto/projects/<project>/tmp/<pid>-<start time>[-<n>]/
//
// and the model reaches it as @tmp, read-only (the program adds it to its
// folder set with FolderSet::add_system). One folder per session, so two
// sessions never see each other's files, and clean-up is removing the folder:
// when the session ends, or at a later start for a session that did not.
//
// A TempFolder is one session's. A program with one session per process
// (tapto-code) uses the process's default one through the functions below;
// one with several (tapto-word: a conversation per document) has one each.
// ---------------------------------------------------------------------------

// A result longer than this is cut.
constexpr std::size_t kOverflowBytes = 16000;
// What of it the model gets inline: whole lines from the start and from the
// end, up to these many bytes each.
constexpr std::size_t kOverflowHeadBytes = 6000;
constexpr std::size_t kOverflowTailBytes = 6000;

class TempFolder {
public:
    TempFolder() = default;
    TempFolder(const TempFolder&) = delete;
    TempFolder& operator=(const TempFolder&) = delete;
    ~TempFolder() { close(); } // removes what open() made

    // Make this session's folder under `parent` (a project's tmp/), after
    // removing those of sessions that are no longer running: of another
    // process that has ended, or of this one and not open now. Returns it, or
    // an empty path (and `error`). It is not written to until use() names it.
    std::filesystem::path open(const std::filesystem::path& parent, std::string& error);

    // Remove what open() made, and stop writing there. Safe to call when
    // nothing was made, and more than once.
    void close();

    // The folder overflow() and write() write to, and the label the model
    // knows it by ("@tmp"). An empty path turns writing off.
    void use(const std::filesystem::path& dir, const std::string& label);

    // `text` as a tool result: itself when it fits in kOverflowBytes;
    // otherwise its head and tail lines with a note naming the lines left out
    // and the file in the folder that holds all of it. `name_hint` (a
    // command's name) starts the file's name. Without a folder, or when the
    // file cannot be written, the cut lines are dropped and the note says so.
    std::string overflow(const std::string& text, const std::string& name_hint);

    // Write `data` to a new file in the folder for the model to read (a
    // plugin's downloaded attachment), named after `name_hint` with a random
    // part so no two collide. Returns the label path ("@tmp/<name>"), or
    // empty and `error` when there is no folder or the file cannot be
    // written.
    std::string write(const std::string& data, const std::string& name_hint, std::string& error);

    const std::filesystem::path& dir() const { return m_dir; }
    const std::string& label() const { return m_label; }

private:
    std::filesystem::path m_made; // what open() made, for close()
    std::filesystem::path m_dir;  // where overflow() and write() write
    std::string m_label;
    unsigned m_count = 0;
};

// The process's default TempFolder, for a program with one session.
TempFolder& default_temp_folder();

// The default one's open(), under the project's tmp/ (the working directory's
// project); close(); use(); overflow(); write().
std::filesystem::path open_session_tmp(std::string& error);
void close_session_tmp();
void set_overflow_folder(const std::filesystem::path& dir, const std::string& label);
std::string overflow(const std::string& text, const std::string& name_hint);
std::string write_temp_file(const std::string& data, const std::string& name_hint,
                            std::string& error);

} // namespace tapto

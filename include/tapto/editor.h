// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#pragma once

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "tapto/fstools.h"
#include "tapto/pathrules.h"
#include "tapto/tool_registry.h"

namespace tapto {

// A program's open documents, which the editor reads and writes in place of
// their files: in an IDE the model then sees the unsaved changes, and its
// edits land in the editor, where the user can undo them. Text is UTF-8 with
// the document's own line endings. Called on the thread that runs the tool,
// with a path the PathRules have already allowed.
class Buffers {
public:
    enum class Result {
        NotOpen,  // no document holds the file: the editor uses the disk
        Done,
        Failed,   // `error` says why
    };
    virtual ~Buffers() = default;
    virtual Result read(const std::filesystem::path& path, std::string& text, std::string& error) = 0;
    virtual Result write(const std::filesystem::path& path, const std::string& text,
                         std::string& error) = 0;
};

// The file editor and file search over a folder set, under its PathRules:
//
//   str_replace_based_edit_tool  view, create, write, delete, str_replace,
//                                insert; declared as Claude's built-in text
//                                editor for Anthropic, with a schema for the
//                                others. Writes only where a folder is rw.
//   find_files                   files by name pattern, optionally with the
//                                lines that hold a string.
//
// Files are read and written byte-exact, and an edit treats any line ending
// as a line ending, so a CRLF file keeps its endings. `folders` must outlive
// the returned specs; the executors hold a reference to it, so a grant made
// later is seen by tools built earlier. The editor's description says where
// it reaches, by whether the set has a home root at the time of the call, so
// set_home() comes first.
//
// With `buffers`, view, write, str_replace and insert go to a document that
// holds the file before the disk; create, delete and find_files use the disk.
std::vector<ToolSpec> editor_tools(const FolderSet& folders,
                                   std::shared_ptr<Buffers> buffers = nullptr);

} // namespace tapto

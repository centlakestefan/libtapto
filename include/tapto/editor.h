// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#pragma once

#include <vector>

#include "tapto/fstools.h"
#include "tapto/pathrules.h"
#include "tapto/tool_registry.h"

namespace tapto {

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
std::vector<ToolSpec> editor_tools(const FolderSet& folders);

} // namespace tapto

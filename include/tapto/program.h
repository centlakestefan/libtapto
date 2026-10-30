// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace tapto {

// The program the library runs in ("tapto-code", "tapto-word", "tapto-vnc",
// "tapto-msvc"), for what the library says to the model and the user:
// "tapto-word's own folders", "tapto-code never writes to a git directory".
// Set once at start, before any tool is built; "tapto" until then.
void set_program_name(const std::string& name);
const std::string& program_name();

// The file the program's code runs from: its executable, or on Windows the
// DLL the library is linked into when a host process loads it (an IDE
// extension in devenv.exe). Plugins must be signed like this file, and sit
// beside it (tapto/plugins.h). Empty if it cannot be found.
std::filesystem::path program_file();

// The tapto programs, whose names may start a config key: the config is
// shared, and "tapto-word.print-cot" is print-cot for tapto-word alone. A
// fixed list, so a misspelt prefix is refused rather than read as a key of
// its own.
const std::vector<std::string>& program_names();

// `key` without a program prefix ("tapto-word.print-cot" -> "print-cot"),
// with the program in `program` (when given); a key without one comes back
// as it is, with `program` empty.
std::string split_program_key(const std::string& key, std::string* program = nullptr);

} // namespace tapto

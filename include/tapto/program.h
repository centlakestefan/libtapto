// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#pragma once

#include <string>

namespace tapto {

// The program the library runs in ("tapto-code", "tapto-word", "tapto-vnc"),
// for what the library says to the model and the user: "tapto-word's own
// folders", "tapto-code never writes to a git directory". Set once at start,
// before any tool is built; "tapto" until then.
void set_program_name(const std::string& name);
const std::string& program_name();

} // namespace tapto

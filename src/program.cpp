// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#include "tapto/program.h"

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

} // namespace tapto

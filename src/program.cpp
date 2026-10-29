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

const std::vector<std::string>& program_names() {
    static const std::vector<std::string> names = {"tapto-code", "tapto-word", "tapto-vnc"};
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

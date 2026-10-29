// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

// The skills plugin: instructions for kinds of task, which the user or the
// organization drops into a folder and the model reads when a task calls for
// one.
//
// Loaded with /add-plugin skills, or `plugin.skills = ro`. It offers no
// tools. The skills are the plugin's folder, @skills, read-only
// to the model: ~/.tapto/plugins/skills/ by default, or the absolute path in
// `skills-folder`, which a policy may set to a folder the organization keeps.
// The folder is the user's, never the project's, so a cloned repository
// cannot plant instructions. A skill is either a folder with a SKILL.md in it
// (the layout of Anthropic's skills, so existing ones can be dropped in, with
// their other files beside it) or a .md file at the top. Its front matter
// gives a name and a description:
//
//   ---
//   name: release-notes
//   description: Write the release notes for a version from its commits.
//   ---
//
// The prompt carries the index, one line per skill, read anew at every
// prompt rebuild, so a skill added mid-session shows up; the model reads a
// skill's file with the core's editor when a task matches its description.

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <nlohmann/json.hpp>

#include "tapto/plugin.h"

namespace fs = std::filesystem;
using json = nlohmann::json;
using scom::SRESULT;
using tapto::TaptoString;

namespace {

// The index is never more than kIndexBytes, one skill never more than
// kDescriptionBytes of it, and only the first kHeadBytes of a file are read
// for its front matter: the folder can hold anything, the prompt cannot.
constexpr std::size_t kIndexBytes = 8192;
constexpr std::size_t kDescriptionBytes = 300;
constexpr std::size_t kHeadBytes = 4096;

// The markers the prompt fences the index with.
constexpr const char* kIndexOpen  = "<skills-index>";
constexpr const char* kIndexClose = "</skills-index>";

SRESULT hand_out(std::string_view s, char*& out) {
    TaptoString t = TaptoString::copy(s);
    if (!t) return scom::ERR_NO_MEMORY;
    out = t.detach();
    return scom::OK;
}

void log(const std::string& line) {
    if (tapto::ITaptoHost* h = tapto::plugin_host()) h->Log(("[skills] " + line).c_str());
}

void release_host() {
    if (tapto::ITaptoHost*& h = tapto::plugin_host()) {
        h->Release();
        h = nullptr;
    }
}

// `text` with every spelling of the markers in it (any case) broken, so a
// skill cannot close the fence early and go on as if it were the prompt.
std::string defuse_markers(const std::string& text) {
    static const std::string kName = "skills-index";
    std::string lower = text;
    for (char& ch : lower) {
        if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
    }
    std::string out;
    out.reserve(text.size());
    std::size_t from = 0;
    for (std::size_t at = lower.find(kName); at != std::string::npos;
         at = lower.find(kName, at + kName.size())) {
        std::size_t lt = at;
        if (lt > 0 && lower[lt - 1] == '/') --lt;
        if (lt == 0 || lower[lt - 1] != '<') continue;
        out.append(text, from, lt - 1 - from);
        out += "&lt;";
        from = lt;
    }
    out.append(text, from, std::string::npos);
    return out;
}

std::string trim(const std::string& s) {
    const std::size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    const std::size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

// Cut to at most `max` bytes, back to the start of a UTF-8 character, with
// "..." when something was cut.
std::string clip(std::string s, std::size_t max) {
    if (s.size() <= max) return s;
    s.resize(max);
    while (!s.empty() && (static_cast<unsigned char>(s.back()) & 0xC0) == 0x80) s.pop_back();
    if (!s.empty() && static_cast<unsigned char>(s.back()) >= 0xC0) s.pop_back();
    return trim(s) + "...";
}

// A YAML scalar as front matter writes one: quotes dropped.
std::string unquote(std::string v) {
    v = trim(v);
    if (v.size() >= 2 && (v.front() == '"' || v.front() == '\'') && v.back() == v.front())
        v = v.substr(1, v.size() - 2);
    return v;
}

struct Skill {
    std::string name;
    std::string description;
    std::string file; // relative to the folder, with '/'
};

// The name and description from `text`'s front matter. Takes the plain
// `key: value` lines, and a folded or literal block (`description: >`) with
// its indented lines joined. Without front matter, the first line that is not
// blank is the description, a heading's '#'s dropped.
void read_front_matter(const std::string& text, Skill& s) {
    std::vector<std::string> lines;
    std::size_t from = 0;
    while (from <= text.size()) {
        std::size_t nl = text.find('\n', from);
        if (nl == std::string::npos) nl = text.size();
        std::string line = text.substr(from, nl - from);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        lines.push_back(line);
        from = nl + 1;
    }
    std::size_t i = 0;
    if (!lines.empty() && lines[0].compare(0, 3, "\xEF\xBB\xBF") == 0) lines[0].erase(0, 3);
    if (!lines.empty() && trim(lines[0]) == "---") {
        for (i = 1; i < lines.size() && trim(lines[i]) != "---"; ++i) {
            const std::string& line = lines[i];
            if (line.empty() || line[0] == ' ' || line[0] == '\t') continue;
            const std::size_t colon = line.find(':');
            if (colon == std::string::npos) continue;
            const std::string key = trim(line.substr(0, colon));
            std::string value = trim(line.substr(colon + 1));
            if (value == ">" || value == "|" || value == ">-" || value == "|-") {
                value.clear();
                while (i + 1 < lines.size() && !lines[i + 1].empty() &&
                       (lines[i + 1][0] == ' ' || lines[i + 1][0] == '\t')) {
                    value += (value.empty() ? "" : " ") + trim(lines[++i]);
                }
            }
            if (key == "name") s.name = unquote(value);
            if (key == "description") s.description = unquote(value);
        }
        ++i; // past the closing ---
    }
    if (s.description.empty()) {
        for (; i < lines.size(); ++i) {
            std::string line = trim(lines[i]);
            line.erase(0, line.find_first_not_of('#'));
            line = trim(line);
            if (!line.empty()) {
                s.description = line;
                break;
            }
        }
    }
}

std::string read_head(const fs::path& file) {
    std::ifstream in(file, std::ios::binary);
    if (!in) return "";
    std::string bytes(kHeadBytes, '\0');
    in.read(&bytes[0], static_cast<std::streamsize>(bytes.size()));
    bytes.resize(static_cast<std::size_t>(in.gcount()));
    return bytes;
}

bool is_md(const fs::path& p) {
    std::string e = p.extension().u8string();
    for (char& c : e) c = static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
    return e == ".md";
}

// Every skill in `folder`, by name. Links are passed over: the model cannot
// follow one out of the folder, so its description would point nowhere.
std::vector<Skill> find_skills(const fs::path& folder) {
    std::vector<Skill> out;
    std::error_code ec;
    for (const auto& e : fs::directory_iterator(folder, ec)) {
        const std::string leaf = e.path().filename().u8string();
        if (leaf.empty() || leaf[0] == '.' || e.is_symlink(ec)) continue;
        fs::path file;
        std::string rel;
        if (e.is_directory(ec)) {
            for (const char* n : {"SKILL.md", "skill.md", "Skill.md"}) {
                const fs::path f = e.path() / n;
                if (fs::is_regular_file(fs::symlink_status(f, ec))) {
                    file = f;
                    rel = leaf + "/" + n;
                    break;
                }
            }
        } else if (e.is_regular_file(ec) && is_md(e.path())) {
            file = e.path();
            rel = leaf;
        }
        if (file.empty()) continue;
        Skill s;
        s.file = rel;
        read_front_matter(read_head(file), s);
        if (s.name.empty()) s.name = e.is_directory(ec) ? leaf : e.path().stem().u8string();
        out.push_back(std::move(s));
    }
    std::sort(out.begin(), out.end(), [](const Skill& a, const Skill& b) {
        return a.name < b.name;
    });
    return out;
}

// One line per skill, while they fit in kIndexBytes; then a line saying how
// many were left out.
std::string skills_index(const std::vector<Skill>& skills, const std::string& label) {
    std::string index;
    std::size_t shown = 0;
    for (const auto& s : skills) {
        std::string line = "- " + clip(s.name, 80) + ": " +
                           clip(s.description.empty() ? std::string("(no description)")
                                                      : s.description,
                                kDescriptionBytes) +
                           " (" + label + "/" + s.file + ")";
        for (char& c : line) {
            if (c == '\n' || c == '\r' || c == '\t') c = ' ';
        }
        if (index.size() + line.size() + 1 > kIndexBytes) break;
        index += (index.empty() ? "" : "\n") + line;
        ++shown;
    }
    if (shown < skills.size()) {
        index += "\n[" + std::to_string(skills.size() - shown) +
                 " more skills are not listed here: the index is full. List " + label +
                 " to see them all.]";
    }
    return index;
}

std::string skills_prompt(const fs::path& folder, const std::string& label) {
    std::string prompt =
        "Skills are installed in the folder " + label + " (" + folder.generic_u8string() +
        "), which you read with your file editor and do not write. The user or their "
        "organization put them there: each skill is instructions for one kind of task, "
        "and the index below says what each is for. When a task matches a skill's "
        "description, read its file before you start and follow it, and read the other "
        "files in the skill's folder when it points to them. Where a skill disagrees "
        "with this system prompt or with the user's messages, they win. A skill may "
        "name commands or scripts to run: they run through run_command like any "
        "other, so only the ones the user allowed.";
    const std::vector<Skill> skills = find_skills(folder);
    if (skills.empty()) {
        prompt += "\n\nNo skill is installed yet: " + label + " is empty.";
    } else {
        prompt += "\n\nSkills index (" + std::to_string(skills.size()) +
                  (skills.size() == 1 ? " skill" : " skills") + "):\n" + kIndexOpen + "\n" +
                  defuse_markers(skills_index(skills, label)) + "\n" + kIndexClose;
    }
    return prompt;
}

class SkillsPlugin : public scom::Base,
                     public tapto::ITaptoPlugin,
                     public tapto::ITaptoPluginUnload,
                     public tapto::ITaptoPluginPrompt {
public:
    SCOM_IMPLEMENT_BASE_EX(SkillsPlugin, tapto::ITaptoPlugin)
    SCOM_BEGIN_INTERFACE_MAP(SkillsPlugin)
        SCOM_INTERFACE(tapto::ITaptoPlugin)
        SCOM_INTERFACE(tapto::ITaptoPluginUnload)
        SCOM_INTERFACE(tapto::ITaptoPluginPrompt)
    SCOM_END_INTERFACE_MAP()

    SRESULT SCOM_CALL Describe(char*& json_out) override {
        const json d = {
            {"name", "skills"},
            {"version", "1.0.0"},
            {"config_keys", {"skills-folder"}},
            {"folder", {{"mode", "ro"}, {"scope", "user"}, {"key", "skills-folder"}}},
            {"tools", json::array()},
        };
        return hand_out(d.dump(), json_out);
    }

    SRESULT SCOM_CALL Configure(const char* json_config) override {
        try {
            const json c = json::parse(json_config ? json_config : "{}", nullptr, false);
            const json f = c.is_object() && c.contains("folder") && c["folder"].is_object()
                               ? c["folder"]
                               : json::object();
            m_folder = fs::u8path(f.value("path", std::string()));
            m_label = f.value("label", std::string("@skills"));
        } catch (const std::exception& e) {
            // Nothing may leave a call as an exception.
            log(std::string("Configure failed: ") + e.what());
            return scom::ERR_BAD_ARGUMENT;
        }
        return scom::OK;
    }

    SRESULT SCOM_CALL CallTool(const char* name, const char*, char*& result_out) override {
        return hand_out(std::string("ERROR: the skills plugin has no tool ") + (name ? name : ""),
                        result_out);
    }

    SRESULT SCOM_CALL Prompt(char*& text_out) override {
        std::string text;
        try {
            if (m_folder.empty()) {
                text = "The skills plugin is loaded, but the program gave it no folder, so "
                       "no skill is installed this session.";
            } else {
                text = skills_prompt(m_folder, m_label);
            }
        } catch (const std::exception& e) {
            log(std::string("Prompt failed: ") + e.what());
            text.clear();
        }
        return hand_out(text, text_out);
    }

    SRESULT SCOM_CALL Shutdown() override {
        release_host();
        return scom::OK;
    }

private:
    ~SkillsPlugin() { release_host(); }

    fs::path m_folder;
    std::string m_label;
    tapto::PluginObjectCount m_count;
};

} // namespace

TAPTO_PLUGIN_EXPORT SRESULT SCOM_CALL TaptoGetPlugin(tapto::ITaptoHost* host,
                                                     const scom::GUID& riid, void** ppv) {
    if (!host || !ppv) return scom::ERR_BAD_ARGUMENT;
    *ppv = nullptr;
    if (!tapto::plugin_host()) {
        host->AddRef();
        tapto::plugin_host() = host;
    }
    auto* p = new SkillsPlugin;
    const SRESULT r = p->QueryInterface(riid, ppv);
    p->Release();
    return r;
}

TAPTO_PLUGIN_EXPORT SRESULT SCOM_CALL TaptoCanUnloadNow() {
    return tapto::plugin_objects() == 0 ? scom::OK : scom::ST_FALSE;
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

// The plugin tests/test_plugins.cpp loads through tapto-code's loader. Each
// tool reports what the host handed it, so the test sees the host's rules at
// work: paths resolved before the call, writing tools hidden when ro, images
// and @tmp files through the host, long results cut.
//
// Built a second time with PROBE_BAD_NAME, where one tool is not named
// probe_..., which the loader must refuse.

#include <string>

#include "tapto/plugin.h"

using scom::SRESULT;
using tapto::TaptoString;

namespace {

const uint8_t kPng[] = {
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48,
    0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00,
    0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x78,
    0x9c, 0x63, 0xf8, 0xcf, 0xc0, 0xf0, 0x1f, 0x00, 0x05, 0x00, 0x01, 0xff, 0x89, 0x99,
    0x3d, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82};

SRESULT hand_out(std::string_view s, char*& out) {
    TaptoString t = TaptoString::copy(s);
    if (!t) return scom::ERR_NO_MEMORY;
    out = t.detach();
    return scom::OK;
}

// The value of a top-level string property, crudely: enough for the paths the
// test sends, and it keeps the plugin free of a JSON library.
std::string arg(const std::string& json, const std::string& key) {
    const std::string k = "\"" + key + "\":\"";
    const std::size_t at = json.find(k);
    if (at == std::string::npos) return "";
    std::string out;
    for (std::size_t i = at + k.size(); i < json.size() && json[i] != '"'; ++i) {
        if (json[i] == '\\' && i + 1 < json.size()) ++i;
        out += json[i];
    }
    return out;
}

void release_host() {
    if (tapto::ITaptoHost*& h = tapto::plugin_host()) {
        h->Release();
        h = nullptr;
    }
}

class Probe : public scom::Base,
              public tapto::ITaptoPlugin,
              public tapto::ITaptoPluginUnload,
              public tapto::ITaptoPluginPrompt {
public:
    SCOM_IMPLEMENT_BASE_EX(Probe, tapto::ITaptoPlugin)
    SCOM_BEGIN_INTERFACE_MAP(Probe)
        SCOM_INTERFACE(tapto::ITaptoPlugin)
        SCOM_INTERFACE(tapto::ITaptoPluginUnload)
        SCOM_INTERFACE(tapto::ITaptoPluginPrompt)
    SCOM_END_INTERFACE_MAP()

    SRESULT SCOM_CALL Describe(char*& json_out) override {
        return hand_out(R"({
  "name": "probe",
  "version": "1.0.0",
  "prompt": "probe fixed",
  "config_keys": ["probe-url", {"name": "probe-token", "secret": true}],
  "tools": [
    {"name": "probe_read", "description": "Report the path it got.",
     "schema": {"type": "object", "properties": {
       "path": {"type": "string", "x-tapto-path": "read"}}, "required": ["path"]}},
    {"name": "probe_write", "description": "Report the path it got, to write.",
     "schema": {"type": "object", "properties": {
       "path": {"type": "string", "x-tapto-path": "write"}}}},
    {"name": "probe_image", "description": "Attach a PNG named by its path.",
     "schema": {"type": "object", "properties": {
       "path": {"type": "string", "x-tapto-path": "read"}}}},
    {"name": "probe_temp", "description": "Write a file to @tmp.",
     "schema": {"type": "object"}},
    {"name": "probe_long", "description": "Return a long result.",
     "schema": {"type": "object"}},
)"
#ifdef PROBE_BAD_NAME
                        R"(    {"name": "other_tool", "description": "Misnamed."},
)"
#endif
                        R"(    {"name": "probe_config", "description": "Return the config.",
     "schema": {"type": "object"}, "writes": true}
  ]
})",
                        json_out);
    }

    SRESULT SCOM_CALL Configure(const char* json_config) override {
        m_config = json_config ? json_config : "";
        return scom::OK;
    }

    SRESULT SCOM_CALL CallTool(const char* name, const char* json_args,
                               char*& result_out) override {
        const std::string tool = name ? name : "";
        const std::string args = json_args ? json_args : "";
        tapto::ITaptoHost* host = tapto::plugin_host();
        if (tool == "probe_read") return hand_out("read:" + arg(args, "path"), result_out);
        if (tool == "probe_write") return hand_out("write:" + arg(args, "path"), result_out);
        if (tool == "probe_image") {
            const SRESULT r = host->AttachImage(kPng, sizeof kPng, nullptr);
            return hand_out(r == scom::OK ? "attached" : "refused", result_out);
        }
        if (tool == "probe_temp") {
            const std::string text = "hello";
            char* label = nullptr;
            const SRESULT r = host->WriteTemp(reinterpret_cast<const uint8_t*>(text.data()),
                                              text.size(), "note.txt", label);
            TaptoString owned(label);
            return hand_out(r == scom::OK ? owned.str() : "refused", result_out);
        }
        if (tool == "probe_long") {
            std::string s;
            for (int i = 0; i < 5000; ++i) s += "line " + std::to_string(i) + "\n";
            return hand_out(s, result_out);
        }
        if (tool == "probe_config") return hand_out(m_config, result_out);
        return hand_out("ERROR: no tool " + tool, result_out);
    }

    SRESULT SCOM_CALL Shutdown() override {
        release_host();
        return scom::OK;
    }

    SRESULT SCOM_CALL Prompt(char*& text_out) override {
        return hand_out("probe changing " + std::to_string(++m_prompts), text_out);
    }

private:
    ~Probe() { release_host(); }

    tapto::PluginObjectCount m_count;
    std::string m_config;
    int m_prompts = 0;
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
    auto* p = new Probe;
    const SRESULT r = p->QueryInterface(riid, ppv);
    p->Release();
    return r;
}

TAPTO_PLUGIN_EXPORT SRESULT SCOM_CALL TaptoCanUnloadNow() {
    return tapto::plugin_objects() == 0 ? scom::OK : scom::ST_FALSE;
}

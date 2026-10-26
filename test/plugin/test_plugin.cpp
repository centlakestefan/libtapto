// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

// The plugin test_plugin.cpp loads: one module built twice, with and without
// ITaptoPluginUnload (TEST_PLUGIN_UNLOAD), so both unload paths are covered.
// It links nothing but the two headers, which is all a plugin needs.
//
// Tools:
//   test_echo       returns its arguments, and the config it was given
//   test_write      the same, declared "writes": true
//   test_wrong_heap returns a string from strdup, which a debug host refuses
//   test_image      attaches a 1x1 PNG through the host
//   test_outside    calls the host's per-call functions from Describe's
//                   caller instead, see `g_outside`

#include <cstdlib>
#include <cstring>
#include <string>

#include "tapto/plugin.h"

using scom::SRESULT;
using tapto::TaptoString;

namespace {

// What IsCancelled returned when Describe (not a call) asked: the host must
// refuse it outside a CallTool. Reported by test_outside.
SRESULT g_outside = -1;

// A valid 1x1 RGBA PNG.
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

void release_host() {
    if (tapto::ITaptoHost*& h = tapto::plugin_host()) {
        h->Release();
        h = nullptr;
    }
}

class Plugin : public scom::Base,
               public tapto::ITaptoPlugin,
#ifdef TEST_PLUGIN_UNLOAD
               public tapto::ITaptoPluginUnload,
#endif
               public tapto::ITaptoPluginPrompt {
public:
    SCOM_IMPLEMENT_BASE_EX(Plugin, tapto::ITaptoPlugin)
    SCOM_BEGIN_INTERFACE_MAP(Plugin)
        SCOM_INTERFACE(tapto::ITaptoPlugin)
#ifdef TEST_PLUGIN_UNLOAD
        SCOM_INTERFACE(tapto::ITaptoPluginUnload)
#endif
        SCOM_INTERFACE(tapto::ITaptoPluginPrompt)
    SCOM_END_INTERFACE_MAP()

    SRESULT SCOM_CALL Describe(char*& json_out) override {
        g_outside = tapto::plugin_host()->IsCancelled();
        return hand_out(R"({
  "name": "test",
  "version": "0.0.1",
  "prompt": "The test plugin is loaded.",
  "config_keys": ["test-url", {"name": "test-token", "secret": true}],
  "tools": [
    {"name": "test_echo", "description": "Echo the arguments.",
     "schema": {"type": "object", "properties": {"text": {"type": "string"}}},
     "writes": false},
    {"name": "test_write", "description": "Echo, declared as writing.",
     "schema": {"type": "object"}, "writes": true},
    {"name": "test_wrong_heap", "description": "Return a strdup'd string.",
     "schema": {"type": "object"}},
    {"name": "test_image", "description": "Attach a 1x1 PNG.",
     "schema": {"type": "object"}},
    {"name": "test_outside", "description": "Report g_outside.",
     "schema": {"type": "object"}}
  ]
})",
                        json_out);
    }

    SRESULT SCOM_CALL Configure(const char* json_config) override {
        if (!json_config) return scom::ERR_BAD_ARGUMENT;
        m_config = json_config;
        return scom::OK;
    }

    SRESULT SCOM_CALL CallTool(const char* name, const char* json_args,
                               char*& result_out) override {
        if (!name || !json_args) return scom::ERR_BAD_ARGUMENT;
        const std::string tool = name;
        tapto::ITaptoHost* host = tapto::plugin_host();
        if (tool == "test_echo" || tool == "test_write") {
            const bool cancelled = host->IsCancelled() == scom::OK;
            return hand_out(std::string("args=") + json_args + " config=" + m_config +
                                (cancelled ? " cancelled" : ""),
                            result_out);
        }
        if (tool == "test_wrong_heap") {
#ifdef _WIN32
            result_out = _strdup("not from MemAlloc");
#else
            result_out = strdup("not from MemAlloc");
#endif
            return scom::OK;
        }
        if (tool == "test_image") {
            const SRESULT r = host->AttachImage(kPng, sizeof kPng, nullptr);
            return hand_out(r == scom::OK ? "attached" : "ERROR: attach refused", result_out);
        }
        if (tool == "test_outside")
            return hand_out(std::to_string(g_outside), result_out);
        return hand_out("ERROR: no tool " + tool, result_out);
    }

#ifdef TEST_PLUGIN_UNLOAD
    SRESULT SCOM_CALL Shutdown() override {
        release_host();
        return scom::OK;
    }
#endif

    SRESULT SCOM_CALL Prompt(char*& text_out) override {
        return hand_out("prompt #" + std::to_string(++m_prompts), text_out);
    }

private:
    ~Plugin() { release_host(); }

    tapto::PluginObjectCount m_count;
    std::string m_config = "{}";
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
    auto* plugin = new Plugin; // one reference, ours
    const SRESULT r = plugin->QueryInterface(riid, ppv);
    plugin->Release();
    return r;
}

TAPTO_PLUGIN_EXPORT SRESULT SCOM_CALL TaptoCanUnloadNow() {
    return tapto::plugin_objects() == 0 ? scom::OK : scom::ST_FALSE;
}

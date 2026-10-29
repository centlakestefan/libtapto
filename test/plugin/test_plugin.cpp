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
//
// ITaptoPluginTools adds test_configured once Configure has run, described
// by what the host's ResolveSecret made of the config's "test-ref".
// ITaptoPluginCommands runs /test, echoing its arguments; ITaptoPluginEvents
// takes before_turn and says something before the first turn only.

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
// What ResolveSecret returned when Describe asked: refused outside Configure.
SRESULT g_secret_outside = -1;

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

class Plugin final : public scom::Base,
               public tapto::ITaptoPlugin,
#ifdef TEST_PLUGIN_UNLOAD
               public tapto::ITaptoPluginUnload,
#endif
               public tapto::ITaptoPluginPrompt,
               public tapto::ITaptoPluginTools,
               public tapto::ITaptoPluginCommands,
               public tapto::ITaptoPluginEvents {
public:
    SCOM_IMPLEMENT_BASE_EX(Plugin, tapto::ITaptoPlugin)
    SCOM_BEGIN_INTERFACE_MAP(Plugin)
        SCOM_INTERFACE(tapto::ITaptoPlugin)
#ifdef TEST_PLUGIN_UNLOAD
        SCOM_INTERFACE(tapto::ITaptoPluginUnload)
#endif
        SCOM_INTERFACE(tapto::ITaptoPluginPrompt)
        SCOM_INTERFACE(tapto::ITaptoPluginTools)
        SCOM_INTERFACE(tapto::ITaptoPluginCommands)
        SCOM_INTERFACE(tapto::ITaptoPluginEvents)
    SCOM_END_INTERFACE_MAP()

    SRESULT SCOM_CALL Describe(char*& json_out) override {
        g_outside = tapto::plugin_host()->IsCancelled();
        g_secret_outside = resolve("env:X", m_secret);
        return hand_out(R"({
  "name": "test",
  "version": "0.0.1",
  "prompt": "The test plugin is loaded.",
  "config_keys": ["test-url", {"name": "test-token", "secret": true}],
  "command": {"usage": "/test <words>", "description": "Echo the words."},
  "events": ["before_turn"],
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
        // The config is JSON; this plugin only looks for one plain string.
        const std::string key = "\"test-ref\":\"";
        const std::size_t at = m_config.find(key);
        if (at != std::string::npos) {
            const std::size_t b = at + key.size(), e = m_config.find('"', b);
            const SRESULT r = resolve(m_config.substr(b, e - b), m_secret);
            m_secret = std::to_string(r) + ":" + m_secret;
            // Kept between sessions, and read back as the host has it.
            scom::QIPtr<tapto::ITaptoHostSecrets> s(tapto::plugin_host());
            if (s && s->StoreSecret("kept", m_secret.c_str()) == scom::OK) {
                TaptoString back;
                if (s->LoadSecret("kept", back.out()) == scom::OK) m_secret = back.str();
            }
        }
        m_configured = true;
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
            return hand_out(std::to_string(g_outside) + " " + std::to_string(g_secret_outside),
                            result_out);
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

    // before_turn: changes nothing, and says so once, before the first.
    SRESULT SCOM_CALL OnEvent(const char* event, const char* json, char*& text_out) override {
        if (!event || std::string(event) != "before_turn" || !json) return scom::ST_FALSE;
        if (m_refreshed++) return scom::ST_FALSE;
        return hand_out("refreshed", text_out);
    }

    SRESULT SCOM_CALL Tools(char*& json_out) override {
        if (!m_configured) return hand_out("[]", json_out);
        return hand_out(R"([{"name": "test_configured", "description": ")" + m_secret +
                            R"(", "schema": {"type": "object"}}])",
                        json_out);
    }

    // /test <args>: the words back, and whether the host counts it as a call.
    SRESULT SCOM_CALL RunCommand(const char* args, char*& text_out) override {
        const SRESULT c = tapto::plugin_host()->IsCancelled();
        return hand_out(std::string("ran ") + (args ? args : "") +
                            (c == scom::ERR_BAD_CONTEXT ? " outside a call" : ""),
                        text_out);
    }

private:
    ~Plugin() { release_host(); }

    // ResolveSecret through the host's optional interface.
    static SRESULT resolve(const std::string& ref, std::string& value) {
        scom::QIPtr<tapto::ITaptoHostSecrets> s(tapto::plugin_host());
        if (!s) return scom::ERR_NOINTERFACE;
        TaptoString v;
        const SRESULT r = s->ResolveSecret(ref.c_str(), v.out());
        value = v.str();
        return r;
    }

    tapto::PluginObjectCount m_count;
    std::string m_config = "{}";
    int m_prompts = 0;
    bool m_configured = false;
    int m_refreshed = 0;
    std::string m_secret;
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

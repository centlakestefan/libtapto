// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#pragma once

// The plugin boundary of the tapto programs: a module (a DLL, an SO) that
// adds tools, loaded by the host program in-process and spoken to through
// sCom interfaces (tapto/scom.h).
//
// JSON crosses the boundary, not typed methods. The tool surface is JSON
// already (schema out, arguments in, text back), so a small vtable carries
// any plugin, and a small vtable stays stable. A new capability is a new
// interface found by QueryInterface, so old plugins load in new hosts and the
// other way round; an interface here never changes once it has shipped.
//
// --- Memory -------------------------------------------------------------------
//
// An in-string is `const char*`; an out string is `char*&` (in C, `char**`:
// the vtable is the same). Every string that crosses and is freed on the other
// side comes from ITaptoHost::MemAlloc and goes back with MemFree, so the
// allocator is always the host's, whatever compiler built the plugin. Inside
// the plugin std::string and its own heap are fine: only what crosses goes
// through TaptoString below.
//
// The one mistake left is handing out a string from another allocator
// (`strdup`, `new char[]`, a statically linked runtime's `malloc`). Do not:
// a debug host refuses to free a block it did not allocate.
//
// No STL crosses, either: MSVC's STL, libstdc++ and libc++ lay out
// std::string differently, and so do MSVC Debug and Release, and a mismatch
// corrupts memory instead of failing to link. A plugin needs only a C ABI, so
// any compiler, and any language with a C FFI, can build one.
//
// Every string is UTF-8, paths included, and no exception may leave a call
// across the boundary: a plugin catches its own and reports them in its
// result.
//
// --- Lifetime -----------------------------------------------------------------
//
// The host calls TaptoGetPlugin once, after loading the module, and keeps the
// host pointer it passes in for as long as the module is loaded. The plugin
// keeps it in tapto::plugin_host() (AddRef'ed, released in Shutdown or when
// its last object goes). To unload, the host releases every pointer it holds,
// after ITaptoPluginUnload::Shutdown if the plugin has that interface, and
// frees the module only when TaptoCanUnloadNow returns OK. A plugin without
// ITaptoPluginUnload stays loaded until the host exits.
//
// All calls come from one thread, the host's agent loop, unless an interface
// says otherwise.

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>

#include "scom.h"

namespace tapto {

using scom::GUID;
using scom::SRESULT;

// What a plugin may ask of the host.
struct ITaptoHost : scom::IBase {
    // The one heap for all memory that crosses the boundary. Aligned as malloc
    // is (alignof(max_align_t)); null on failure. MemFree takes null.
    virtual void* SCOM_CALL MemAlloc(size_t size) = 0;
    virtual void SCOM_CALL MemFree(void* p) = 0;

    // One line to the host's trace file.
    virtual SRESULT SCOM_CALL Log(const char* line) = 0;

    // The rest act on the CallTool in progress, and return
    // scom::ERR_BAD_CONTEXT outside one.

    // OK when the user has cancelled (ESC), ST_FALSE when not: a long call
    // polls it and returns early.
    virtual SRESULT SCOM_CALL IsCancelled() = 0;

    // Puts a file in the session's @tmp for the model to read (a downloaded
    // attachment). `label_path_out` is "@tmp/<name>", for the result text.
    virtual SRESULT SCOM_CALL WriteTemp(const uint8_t* data, size_t size,
                                        const char* name_hint,
                                        char*& label_path_out) = 0;

    // Attaches a PNG to the call's result, for a model that can see. The host
    // checks the signature, reads width and height from the PNG itself and
    // caps the size. A null `label` names the image by the call's path
    // argument (x-tapto-path), as the model wrote it.
    virtual SRESULT SCOM_CALL AttachImage(const uint8_t* png, size_t size,
                                          const char* label) = 0;
};
// {2924B32E-5182-4042-98A1-7C616A32A385}
SCOM_DEFINE_IID(ITaptoHost, 0x2924b32e, 0x5182, 0x4042, 0x98, 0xa1, 0x7c, 0x61, 0x6a,
                0x32, 0xa3, 0x85)

// Found on the host by QueryInterface: secrets a plugin finds in its own
// settings, and secrets it keeps between sessions.
struct ITaptoHostSecrets : scom::IBase {
    // Resolves `ref`, from the plugin's own settings rather than a config key
    // it declared secret (a file of server definitions, say), the way the
    // host resolves such a key: "env:NAME", "cmd:<command>",
    // "wincred:<target>", or a plain value, which is the secret itself. Only
    // during Configure or RunCommand (both read the user's settings at the
    // user's word); ERR_BAD_CONTEXT outside them. ERR_NOT_FOUND when a
    // reference cannot be resolved, and then `value_out` is the reason, for
    // the plugin's own message.
    virtual SRESULT SCOM_CALL ResolveSecret(const char* ref, char*& value_out) = 0;

    // A secret the plugin keeps between sessions (a token it was given at a
    // login), in the user's secret store: Windows Credential Manager, a file
    // only the user can read elsewhere. Each plugin has its own names, so it
    // reaches no other plugin's and no credential of the user's. `name` is
    // [A-Za-z0-9._-], at most 64; an empty `value` forgets it. During
    // Configure, CallTool or RunCommand; ERR_BAD_CONTEXT outside them.
    virtual SRESULT SCOM_CALL StoreSecret(const char* name, const char* value) = 0;
    // What StoreSecret kept under `name`; ERR_NOT_FOUND when nothing is.
    virtual SRESULT SCOM_CALL LoadSecret(const char* name, char*& value_out) = 0;
};
// {64DF3181-B47F-49C9-86B6-54FA53702042}
SCOM_DEFINE_IID(ITaptoHostSecrets, 0x64df3181, 0xb47f, 0x49c9, 0x86, 0xb6, 0x54, 0xfa,
                0x53, 0x70, 0x20, 0x42)

// The plugin itself, what TaptoGetPlugin hands out.
//
// Describe's JSON:
//
//   {
//     "name": "image",                 // [a-z][a-z0-9-]*, the module's name
//     "version": "1.0.0",
//     "prompt": "...",                 // optional, fixed system-prompt text
//     "config_keys": ["jira-url", {"name": "jira-api-token", "secret": true}],
//     "folder": "rw",                  // optional, "ro" or "rw": a folder
//                                      // of the plugin's own, per project
//     "command": {"usage": "...", "description": "..."}, // optional: the
//                                      // command /<name>, see
//                                      // ITaptoPluginCommands
//     "events": ["before_turn"],       // optional: see ITaptoPluginEvents
//     "tools": [{
//       "name": "image_read",          // must start with "<name>_"
//       "description": "...",
//       "schema": {...},               // JSON Schema of the arguments; a
//                                      // string property with
//                                      // "x-tapto-path": "read" | "write"
//                                      // is a path the host resolves and
//                                      // checks before CallTool
//       "writes": false                // true: offered only when loaded rw
//     }]
//   }
//
// A plugin's folder is reached by the model as "@<name>" (the plugin's name),
// with the host's path rules and its editor, so the plugin need not offer
// file tools of its own. It is read-only when the folder says "ro" or the
// plugin is loaded ro. The host makes it, and passes it to Configure.
struct ITaptoPlugin : scom::IBase {
    virtual SRESULT SCOM_CALL Describe(char*& json_out) = 0;
    // An object of the plugin's config keys, secrets already resolved by the
    // host. Called before the first CallTool, and again when one changes or
    // the plugin's mode does. A plugin with a folder also finds it there,
    // under a name no config key can have:
    //   "folder": {"path": "<absolute>", "label": "@<name>", "writable": true}
    // Every plugin finds its place among the user's settings, a folder the
    // host neither makes nor lets the model reach, for files of the user's
    // own that the plugin reads (a list of servers, say):
    //   "user_folder": "<absolute>"
    virtual SRESULT SCOM_CALL Configure(const char* json_config) = 0;
    // `json_args` is the model's arguments, path arguments replaced by the
    // checked absolute path. `result_out` is the text the model gets; a tool
    // that fails says so there, starting with "ERROR: ", and returns OK. An
    // error status is for a call the plugin could not make at all.
    virtual SRESULT SCOM_CALL CallTool(const char* name, const char* json_args,
                                       char*& result_out) = 0;
};
// {DB9B3100-2A2C-4F52-A9E4-CD9CB40C1BA0}
SCOM_DEFINE_IID(ITaptoPlugin, 0xdb9b3100, 0x2a2c, 0x4f52, 0xa9, 0xe4, 0xcd, 0x9c, 0xb4,
                0x0c, 0x1b, 0xa0)

// Optional: a plugin that can be unloaded. Shutdown closes connections and
// stops threads; the host releases its pointers after it.
struct ITaptoPluginUnload : scom::IBase {
    virtual SRESULT SCOM_CALL Shutdown() = 0;
};
// {A3027652-8645-4DA2-B446-58A77F5343E9}
SCOM_DEFINE_IID(ITaptoPluginUnload, 0xa3027652, 0x8645, 0x4da2, 0xb4, 0x46, 0x58, 0xa7,
                0x7f, 0x53, 0x43, 0xe9)

// Optional: system-prompt text that changes, asked for each time the host
// rebuilds the prompt (Describe's "prompt" is fixed).
struct ITaptoPluginPrompt : scom::IBase {
    virtual SRESULT SCOM_CALL Prompt(char*& text_out) = 0;
};
// {D93075D6-02D3-4566-8B2D-2C94BC3DD0D4}
SCOM_DEFINE_IID(ITaptoPluginPrompt, 0xd93075d6, 0x02d3, 0x4566, 0x8b, 0x2d, 0x2c, 0x94,
                0xbc, 0x3d, 0xd0, 0xd4)

// Optional: tools known only once the plugin is configured (a bridge to
// servers it connects to in Configure). Asked for after every Configure,
// CallTool, RunCommand and OnEvent, since those may change them (a server that wants a
// login again, a login); the JSON array it hands out replaces Describe's
// "tools", in the same shape and under the same rules. A host takes a change
// made by a call from the model's next turn. A failed call leaves the plugin
// with no tools.
struct ITaptoPluginTools : scom::IBase {
    virtual SRESULT SCOM_CALL Tools(char*& json_out) = 0;
};
// {84BCF703-90E0-4B71-9056-596BFB228620}
SCOM_DEFINE_IID(ITaptoPluginTools, 0x84bcf703, 0x90e0, 0x4b71, 0x90, 0x56, 0x59, 0x6b,
                0xfb, 0x22, 0x86, 0x20)

// Optional: what happens in the host, for a plugin that subscribed to it in
// Describe ("events": ["before_turn"]); only those events reach it, so an
// event added to a later host never surprises an older plugin. Each is run
// as a RunCommand is (the per-call host functions and secrets work). OK when
// the plugin's tools or prompt may have changed, and the host asks for them
// again; ST_FALSE when nothing did. `text_out`, when set, is printed to the
// user.
//
// Events are notifications: one never decides what the host does. A plugin
// that takes a decision over (runs a command elsewhere, say) does it through
// an interface of its own.
//
// The events, with what `json` holds:
//
//   before_turn  {}  before each of the model's turns, after the user's
//                    message is in. A plugin whose own settings changed on
//                    disk (a file it reads) takes them in here; it should
//                    cost nothing when nothing changed, a stat, not a read.
struct ITaptoPluginEvents : scom::IBase {
    virtual SRESULT SCOM_CALL OnEvent(const char* event, const char* json, char*& text_out) = 0;
};
// {2D438FD3-248A-4D88-B23D-7C76DF25ECB4}
SCOM_DEFINE_IID(ITaptoPluginEvents, 0x2d438fd3, 0x248a, 0x4d88, 0xb2, 0x3d, 0x7c, 0x76, 0xdf,
                0x25, 0xec, 0xb4)

// Optional: a command the user types, "/<name> <args>", named after the
// plugin so it can shadow neither the host's commands nor another plugin's.
// Describe says it has one:
//   "command": {"usage": "/mcp list | login <server>", "description": "..."}
// `args` is the rest of the line, trimmed; `text_out` is printed to the user
// and never reaches the model. The host runs it as it runs a CallTool, so the
// per-call host functions work (IsCancelled: ESC), and asks for the tools
// and the prompt again after it. An error status is for a command the plugin
// could not run at all; one that fails says so in its text.
struct ITaptoPluginCommands : scom::IBase {
    virtual SRESULT SCOM_CALL RunCommand(const char* args, char*& text_out) = 0;
};
// {D2BBA127-9AE5-4BFC-B861-7BA9A7E470B0}
SCOM_DEFINE_IID(ITaptoPluginCommands, 0xd2bba127, 0x9ae5, 0x4bfc, 0xb8, 0x61, 0x7b, 0xa9,
                0xa7, 0xe4, 0x70, 0xb0)

// --- The module's exports -----------------------------------------------------

#if defined(_WIN32)
#  define TAPTO_PLUGIN_EXPORT extern "C" __declspec(dllexport)
#else
#  define TAPTO_PLUGIN_EXPORT extern "C" __attribute__((visibility("default")))
#endif

// Names the host looks the exports up by.
constexpr const char* kGetPluginExport = "TaptoGetPlugin";
constexpr const char* kCanUnloadNowExport = "TaptoCanUnloadNow";

// TaptoGetPlugin(host, riid, ppv): the host comes first, so the plugin can
// allocate before its first call returns. riid is IID_ITaptoPlugin.
// TaptoCanUnloadNow(): OK once no object of the module is alive.
using GetPluginFn = SRESULT(SCOM_CALL*)(ITaptoHost* host, const GUID& riid, void** ppv);
using CanUnloadNowFn = SRESULT(SCOM_CALL*)();

// --- Both sides ---------------------------------------------------------------

// The host this module talks to. In a plugin, TaptoGetPlugin sets it; in the
// host, it points at the host's own ITaptoHost. One per module, since a module
// is loaded once per process and its host outlives it.
inline ITaptoHost*& plugin_host() {
    static ITaptoHost* host = nullptr;
    return host;
}

// Live objects of this module, for TaptoCanUnloadNow. A plugin object holds a
// PluginObjectCount member, or counts by hand.
inline std::atomic<int32_t>& plugin_objects() {
    static std::atomic<int32_t> n{0};
    return n;
}
struct PluginObjectCount {
    PluginObjectCount() { ++plugin_objects(); }
    PluginObjectCount(const PluginObjectCount&) { ++plugin_objects(); }
    ~PluginObjectCount() { --plugin_objects(); }
};

// A string from the host's heap (plugin_host()->MemAlloc), freed with
// MemFree. What crosses the boundary goes through one of these.
//
//   TaptoString r = TaptoString::copy(text);
//   result_out = r.detach();             // the callee hands one out
//
//   TaptoString s;
//   plugin->Describe(s.out());           // the caller owns what comes back
class TaptoString {
public:
    TaptoString() = default;
    // Takes over a string that came from MemAlloc.
    explicit TaptoString(char* owned) : m_p(owned) {}
    TaptoString(const TaptoString&) = delete;
    TaptoString& operator=(const TaptoString&) = delete;
    TaptoString(TaptoString&& o) noexcept : m_p(o.m_p) { o.m_p = nullptr; }
    TaptoString& operator=(TaptoString&& o) noexcept {
        if (this != &o) {
            reset();
            m_p = o.m_p;
            o.m_p = nullptr;
        }
        return *this;
    }
    ~TaptoString() { reset(); }

    // A copy of `s` on the host's heap; empty (null) when MemAlloc fails.
    static TaptoString copy(std::string_view s) {
        TaptoString t;
        if (ITaptoHost* h = plugin_host()) {
            if (auto* p = static_cast<char*>(h->MemAlloc(s.size() + 1))) {
                if (!s.empty()) std::memcpy(p, s.data(), s.size());
                p[s.size()] = '\0';
                t.m_p = p;
            }
        }
        return t;
    }

    // For an out parameter: frees what it held, so the callee can store.
    char*& out() {
        reset();
        return m_p;
    }
    // Passes ownership on; the string is the receiver's to free.
    char* detach() {
        char* p = m_p;
        m_p = nullptr;
        return p;
    }
    void reset() {
        if (m_p) {
            if (ITaptoHost* h = plugin_host()) h->MemFree(m_p);
            m_p = nullptr;
        }
    }

    const char* c_str() const { return m_p ? m_p : ""; }
    std::string str() const { return c_str(); }
    bool empty() const { return !m_p || !*m_p; }
    explicit operator bool() const { return m_p != nullptr; }

private:
    char* m_p = nullptr;
};

} // namespace tapto

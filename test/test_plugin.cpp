// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

// The plugin boundary (tapto/plugin.h) from the host's side: load the test
// plugin, describe it, configure it, call its tools, and unload it, both with
// ITaptoPluginUnload and without. The host here is a debug host: it tracks
// every block it allocates and refuses to free one it did not, which is how
// a plugin returning a strdup'd string is caught.
//
// Takes the two builds of the test plugin as arguments:
//   test-plugin <with-unload module> <without-unload module>

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <utility>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#else
#  include <dlfcn.h>
#endif

#include <nlohmann/json.hpp>

#include "tapto/plugin.h"

using nlohmann::json;
using scom::SRESULT;
using tapto::TaptoString;

namespace {

int g_failures = 0;

#define CHECK(cond)                                                              \
    do {                                                                         \
        if (!(cond)) {                                                           \
            std::cerr << __FILE__ << ":" << __LINE__ << ": CHECK failed: " #cond \
                      << "\n";                                                   \
            ++g_failures;                                                        \
        }                                                                        \
    } while (0)

#define CHECK_EQ(a, b)                                                           \
    do {                                                                         \
        const auto& _a = (a);                                                    \
        const auto& _b = (b);                                                    \
        if (!(_a == _b)) {                                                       \
            std::cerr << __FILE__ << ":" << __LINE__ << ": CHECK_EQ failed: "    \
                      << #a << " == " << #b << "\n  got: " << _a                 \
                      << "\n  want: " << _b << "\n";                             \
            ++g_failures;                                                        \
        }                                                                        \
    } while (0)

// --- the debug host -------------------------------------------------------------

class TestHost : public tapto::ITaptoHost, public tapto::ITaptoHostSecrets {
public:
    SRESULT SCOM_CALL QueryInterface(const scom::GUID& riid, void** ppv) override {
        if (!ppv) return scom::ERR_BAD_ARGUMENT;
        if (scom::IsEqualGUID(riid, scom::IID_IBase) ||
            scom::IsEqualGUID(riid, tapto::IID_ITaptoHost)) {
            *ppv = static_cast<tapto::ITaptoHost*>(this);
            AddRef();
            return scom::OK;
        }
        if (scom::IsEqualGUID(riid, tapto::IID_ITaptoHostSecrets)) {
            *ppv = static_cast<tapto::ITaptoHostSecrets*>(this);
            AddRef();
            return scom::OK;
        }
        *ppv = nullptr;
        return scom::ERR_NOINTERFACE;
    }
    // Counted, but never deleted: the host outlives every plugin, and the
    // count shows whether a plugin let go of it.
    uint32_t SCOM_CALL AddRef() override { return static_cast<uint32_t>(++refs); }
    uint32_t SCOM_CALL Release() override { return static_cast<uint32_t>(--refs); }

    void* SCOM_CALL MemAlloc(size_t size) override {
        void* p = std::malloc(size ? size : 1);
        if (p) live.insert(p);
        return p;
    }
    void SCOM_CALL MemFree(void* p) override {
        if (!p) return;
        if (live.erase(p) == 0) {
            // Not ours: freeing it would corrupt another heap. Leak it.
            ++foreign_frees;
            return;
        }
        std::free(p);
    }
    SRESULT SCOM_CALL Log(const char* line) override {
        log += line ? line : "";
        log += '\n';
        return scom::OK;
    }
    SRESULT SCOM_CALL IsCancelled() override {
        if (!in_call) return scom::ERR_BAD_CONTEXT;
        return cancelled ? scom::OK : scom::ST_FALSE;
    }
    SRESULT SCOM_CALL WriteTemp(const uint8_t*, size_t, const char*, char*&) override {
        return in_call ? scom::ERR_NOT_FOUND : scom::ERR_BAD_CONTEXT;
    }
    SRESULT SCOM_CALL AttachImage(const uint8_t* png, size_t size, const char*) override {
        if (!in_call) return scom::ERR_BAD_CONTEXT;
        if (!png || size < 8) return scom::ERR_BAD_ARGUMENT;
        image_bytes = size;
        return scom::OK;
    }

    // "bad:..." fails; anything else resolves to "secret(<ref>)".
    SRESULT SCOM_CALL ResolveSecret(const char* ref, char*& value_out) override {
        if (!in_configure) return scom::ERR_BAD_CONTEXT;
        const std::string r = ref ? ref : "";
        const bool bad = r.rfind("bad:", 0) == 0;
        TaptoString v = TaptoString::copy(bad ? "cannot resolve " + r : "secret(" + r + ")");
        MemFree(value_out);
        value_out = v.detach();
        return bad ? scom::ERR_NOT_FOUND : scom::OK;
    }
    SRESULT SCOM_CALL StoreSecret(const char* name, const char* value) override {
        if (!in_configure && !in_call) return scom::ERR_BAD_CONTEXT;
        if (!name || !*name) return scom::ERR_BAD_ARGUMENT;
        if (!value || !*value) secrets.erase(name);
        else secrets[name] = value;
        return scom::OK;
    }
    SRESULT SCOM_CALL LoadSecret(const char* name, char*& value_out) override {
        if (!in_configure && !in_call) return scom::ERR_BAD_CONTEXT;
        const auto it = secrets.find(name ? name : "");
        if (it == secrets.end()) return scom::ERR_NOT_FOUND;
        TaptoString v = TaptoString::copy(it->second);
        MemFree(value_out);
        value_out = v.detach();
        return scom::OK;
    }
    std::map<std::string, std::string> secrets;

    int refs = 0;
    std::set<void*> live;
    int foreign_frees = 0;
    std::string log;
    bool in_call = false;
    bool in_configure = false;
    bool cancelled = false;
    size_t image_bytes = 0;
};

TestHost g_host;

// A call the way the host makes it: inside one, the per-call functions work.
SRESULT call(tapto::ITaptoPlugin* p, const char* name, const char* args, TaptoString& out) {
    g_host.in_call = true;
    const SRESULT r = p->CallTool(name, args, out.out());
    g_host.in_call = false;
    return r;
}

// Configure the way the host does it: secrets resolve during it.
SRESULT configure(tapto::ITaptoPlugin* p, const char* config) {
    g_host.in_configure = true;
    const SRESULT r = p->Configure(config);
    g_host.in_configure = false;
    return r;
}

// The tools ITaptoPluginTools hands out now.
json tools_of(tapto::ITaptoPlugin* p) {
    scom::QIPtr<tapto::ITaptoPluginTools> t(p);
    if (!t) return json();
    TaptoString s;
    if (t->Tools(s.out()) != scom::OK) return json();
    return json::parse(s.c_str(), nullptr, false);
}

// --- loading --------------------------------------------------------------------

struct Module {
#ifdef _WIN32
    HMODULE h = nullptr;
    bool open(const std::string& path) { return (h = LoadLibraryA(path.c_str())) != nullptr; }
    void* sym(const char* name) {
        return reinterpret_cast<void*>(GetProcAddress(h, name));
    }
    bool close() { return FreeLibrary(h) != 0; }
#else
    void* h = nullptr;
    bool open(const std::string& path) {
        return (h = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL)) != nullptr;
    }
    void* sym(const char* name) { return dlsym(h, name); }
    bool close() { return dlclose(h) == 0; }
#endif
};

// Loads the module, exercises it, and unloads it. `has_unload` says which
// build it is.
void test_module(const std::string& path, bool has_unload) {
    std::cerr << "module: " << path << "\n";
    Module m;
    if (!m.open(path)) {
        std::cerr << "  could not load it\n";
        ++g_failures;
        return;
    }
    auto get = reinterpret_cast<tapto::GetPluginFn>(m.sym(tapto::kGetPluginExport));
    auto can_unload =
        reinterpret_cast<tapto::CanUnloadNowFn>(m.sym(tapto::kCanUnloadNowExport));
    CHECK(get != nullptr);
    CHECK(can_unload != nullptr);
    if (!get || !can_unload) return;

    // An interface it does not have: refused, nothing left alive.
    {
        void* pv = reinterpret_cast<void*>(1);
        CHECK_EQ(get(&g_host, tapto::IID_ITaptoHost, &pv), scom::ERR_NOINTERFACE);
        CHECK(pv == nullptr);
        CHECK_EQ(can_unload(), scom::OK);
        CHECK_EQ(g_host.refs, 0);
    }

    scom::Ptr<tapto::ITaptoPlugin> plugin;
    CHECK_EQ(get(&g_host, tapto::IID_ITaptoPlugin, reinterpret_cast<void**>(&plugin)),
             scom::OK);
    if (!plugin) return;
    CHECK(g_host.refs > 0);                  // the plugin keeps the host
    CHECK_EQ(can_unload(), scom::ST_FALSE); // and an object is alive

    // Describe, parsed the way the host will.
    {
        TaptoString desc;
        CHECK_EQ(plugin->Describe(desc.out()), scom::OK);
        json d = json::parse(desc.c_str(), nullptr, false);
        CHECK(!d.is_discarded());
        CHECK_EQ(d.value("name", std::string()), std::string("test"));
        CHECK_EQ(d["tools"].size(), std::size_t(5));
        CHECK_EQ(d["tools"][1].value("writes", false), true);
        CHECK_EQ(d["config_keys"][1].value("secret", false), true);
        CHECK_EQ(d["command"].value("usage", std::string()), std::string("/test <words>"));
        CHECK_EQ(d["events"].dump(), std::string(R"(["before_turn"])"));
    }

    // Per-call host functions refuse outside a call (Describe asked).
    {
        TaptoString r;
        CHECK_EQ(call(plugin, "test_outside", "{}", r), scom::OK);
        CHECK_EQ(r.str(), std::to_string(scom::ERR_BAD_CONTEXT) + " " +
                              std::to_string(scom::ERR_BAD_CONTEXT));
    }

    // No tools of its own until it is configured.
    CHECK_EQ(tools_of(plugin), json::array());

    // before_turn: a change once, then none; an event it did not ask for, none.
    {
        scom::QIPtr<tapto::ITaptoPluginEvents> e(plugin.get());
        CHECK(e);
        TaptoString text;
        if (e) {
            CHECK_EQ(e->OnEvent("after_turn", "{}", text.out()), scom::ST_FALSE);
            CHECK_EQ(e->OnEvent("before_turn", "{}", text.out()), scom::OK);
            CHECK_EQ(text.str(), std::string("refreshed"));
            CHECK_EQ(e->OnEvent("before_turn", "{}", text.out()), scom::ST_FALSE);
            CHECK(text.empty());
        }
    }

    // Configure, then a call sees the config and the cancel flag.
    {
        CHECK_EQ(configure(plugin, R"({"test-url":"http://x"})"), scom::OK);
        TaptoString r;
        CHECK_EQ(call(plugin, "test_echo", R"({"text":"hi"})", r), scom::OK);
        CHECK_EQ(r.str(), std::string(R"(args={"text":"hi"} config={"test-url":"http://x"})"));
        g_host.cancelled = true;
        CHECK_EQ(call(plugin, "test_write", "{}", r), scom::OK);
        CHECK(r.str().find(" cancelled") != std::string::npos);
        g_host.cancelled = false;
    }

    // Configured with a reference: resolved through the host, and the tools
    // it then lists say what came back.
    {
        CHECK_EQ(configure(plugin, R"({"test-ref":"env:TOKEN"})"), scom::OK);
        const json t = tools_of(plugin);
        CHECK_EQ(t.size(), std::size_t(1));
        CHECK_EQ(t[0].value("name", std::string()), std::string("test_configured"));
        CHECK_EQ(t[0].value("description", std::string()), std::string("0:secret(env:TOKEN)"));
        // It kept what it resolved, and read it back.
        CHECK_EQ(g_host.secrets["kept"], std::string("0:secret(env:TOKEN)"));
        CHECK_EQ(configure(plugin, R"({"test-ref":"bad:x"})"), scom::OK);
        CHECK_EQ(tools_of(plugin)[0].value("description", std::string()),
                 std::to_string(scom::ERR_NOT_FOUND) + ":cannot resolve bad:x");
    }

    // An image goes through the host.
    {
        g_host.image_bytes = 0;
        TaptoString r;
        CHECK_EQ(call(plugin, "test_image", "{}", r), scom::OK);
        CHECK_EQ(r.str(), std::string("attached"));
        CHECK(g_host.image_bytes > 8);
    }

    // A string from strdup: the debug host refuses to free it.
    {
        const int before = g_host.foreign_frees;
        TaptoString r;
        CHECK_EQ(call(plugin, "test_wrong_heap", "{}", r), scom::OK);
        r.reset();
        CHECK_EQ(g_host.foreign_frees, before + 1);
    }

    // The smart pointers' copies and moves keep the count right.
    {
        scom::Ptr<tapto::ITaptoPlugin> a(plugin.get()), b;
        b = a;                      // copy: two references more than `plugin`
        scom::Ptr<tapto::ITaptoPlugin> c(std::move(a));
        CHECK(!a && c.get() == plugin.get());
        b = std::move(c);           // move-assign: b's old reference released
        CHECK(!c && b.get() == plugin.get());
        scom::QIPtr<tapto::ITaptoPluginPrompt> q;
        q = scom::QIPtr<tapto::ITaptoPluginPrompt>(plugin.get());
        CHECK(q);
    }

    // A command, run as a call is.
    {
        scom::QIPtr<tapto::ITaptoPluginCommands> cmd(plugin.get());
        CHECK(cmd);
        if (cmd) {
            TaptoString t;
            g_host.in_call = true;
            CHECK_EQ(cmd->RunCommand("a b", t.out()), scom::OK);
            g_host.in_call = false;
            CHECK_EQ(t.str(), std::string("ran a b"));
        }
    }

    // The optional interfaces, by QueryInterface.
    {
        scom::QIPtr<tapto::ITaptoPluginPrompt> prompt(plugin.get());
        CHECK(prompt);
        if (prompt) {
            TaptoString t;
            CHECK_EQ(prompt->Prompt(t.out()), scom::OK);
            CHECK_EQ(t.str(), std::string("prompt #1"));
            CHECK_EQ(prompt->Prompt(t.out()), scom::OK); // out() frees the first
            CHECK_EQ(t.str(), std::string("prompt #2"));
        }
    }

    // Unload, as /remove-plugin does it.
    scom::QIPtr<tapto::ITaptoPluginUnload> unload(plugin.get());
    CHECK_EQ(static_cast<bool>(unload), has_unload);
    if (unload) {
        CHECK_EQ(unload->Shutdown(), scom::OK);
        CHECK_EQ(g_host.refs, 0); // Shutdown let go of the host
    }
    unload.Release();
    plugin.Release();
    CHECK_EQ(g_host.refs, 0);
    CHECK_EQ(can_unload(), scom::OK);

    // Every block the host handed out came back, except the one the plugin
    // never got from it.
    CHECK(g_host.live.empty());

    // Without ITaptoPluginUnload the host keeps the module loaded until exit;
    // the test frees both, since nothing of either is alive any more.
    CHECK(m.close());
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: test-plugin <with-unload module> <without-unload module>\n";
        return 2;
    }
    tapto::plugin_host() = &g_host;

    // TaptoString in the host, through the same global.
    {
        TaptoString s = TaptoString::copy("abc");
        CHECK_EQ(s.str(), std::string("abc"));
        CHECK_EQ(g_host.live.size(), std::size_t(1));
        char* p = s.detach();
        CHECK(s.empty());
        TaptoString t(p);
        t.reset();
        CHECK(g_host.live.empty());
        CHECK(TaptoString::copy("").c_str()[0] == '\0');
    }

    test_module(argv[1], true);
    test_module(argv[2], false);

    if (g_failures) {
        std::cerr << g_failures << " check(s) failed\n";
        return 1;
    }
    std::cerr << "all plugin tests passed\n";
    return 0;
}

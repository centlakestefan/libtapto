// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#include "tapto/plugins.h"

#include "tapto/fstools.h"
#include "tapto/log.h"
#include "tapto/overflow.h"
#include "tapto/pathrules.h"
#include "tapto/paths.h"
#include "tapto/plugin.h"
#include "tapto/policy.h"
#include "tapto/program.h"
#include "tapto/provider.h"
#include "tapto/secret.h"
#include "tapto/tool_image.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <mutex>
#include <set>
#include <sstream>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#  include <softpub.h>
#  include <wincred.h>
#  include <wincrypt.h>
#  include <wintrust.h>
#else
#  include <dlfcn.h>
#  include <unistd.h>
#  ifdef __APPLE__
#    include <mach-o/dyld.h>
#  endif
#endif

#include <nlohmann/json.hpp>

// Release builds on Windows check a module's signature before loading it;
// Debug builds and the tests, which load modules built moments ago, do not.
// Elsewhere the root-owned install directory does that job (load_module).
#if defined(_WIN32) && defined(NDEBUG) && !defined(TAPTO_PLUGINS_ALLOW_UNSIGNED)
#  define TAPTO_PLUGINS_VERIFY 1
#endif

namespace fs = std::filesystem;
using json = nlohmann::json;
using scom::SRESULT;

namespace tapto {

namespace {

// Past these a PNG is refused: the model sees a fraction of a megapixel, and
// the history is re-sent on every request.
constexpr std::size_t kMaxImageBytes = 20u << 20;
constexpr uint32_t kMaxImageSide = 16384;

#ifdef _WIN32
const char* const kModuleExt = ".dll";
#else
const char* const kModuleExt = ".so";
#endif

bool is_false(std::string v) {
    std::transform(v.begin(), v.end(), v.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return v == "0" || v == "false" || v == "off" || v == "no";
}

std::string trim(const std::string& s) {
    const std::size_t b = s.find_first_not_of(" \t");
    if (b == std::string::npos) return "";
    const std::size_t e = s.find_last_not_of(" \t");
    return s.substr(b, e - b + 1);
}

std::vector<std::string> split_list(const std::string& value) {
    std::vector<std::string> out;
    std::stringstream ss(value);
    std::string item;
    while (std::getline(ss, item, ',')) {
        item = trim(item);
        if (!item.empty()) out.push_back(item);
    }
    return out;
}

// [a-z][a-z0-9-]*: a file name, a config prefix and a tool-name prefix alike.
bool is_valid_plugin_name(const std::string& name) {
    if (name.empty() || name.size() > 32 || !(name[0] >= 'a' && name[0] <= 'z')) return false;
    for (char c : name) {
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return false;
    }
    return true;
}

// --- the allocator -------------------------------------------------------------
//
// One heap for every block that crosses, whichever plugin it goes to. A debug
// build tracks the blocks it handed out and refuses to free any other: a
// plugin that returns a string from its own heap would otherwise corrupt
// this one, far from the mistake.

#ifndef NDEBUG
std::mutex& live_mutex() {
    static std::mutex m;
    return m;
}
std::set<void*>& live_blocks() {
    static std::set<void*> s;
    return s;
}
#endif

void* mem_alloc(std::size_t size) {
    void* p = std::malloc(size ? size : 1);
#ifndef NDEBUG
    if (p) {
        std::lock_guard<std::mutex> lock(live_mutex());
        live_blocks().insert(p);
    }
#endif
    return p;
}

void mem_free(void* p, const std::string& who) {
    if (!p) return;
#ifndef NDEBUG
    {
        std::lock_guard<std::mutex> lock(live_mutex());
        if (live_blocks().erase(p) == 0) {
            mclog("[plugin " + who + "] BUG: freed a block the host did not allocate; leaked "
                  "instead (a string from strdup or the plugin's own heap?)\n");
            return;
        }
    }
#else
    (void)who;
#endif
    std::free(p);
}

// --- a plugin's secrets ------------------------------------------------------------

#ifdef _WIN32
std::wstring widen(const std::string& s);
#endif

bool is_valid_secret_name(const std::string& name) {
    if (name.empty() || name.size() > 64) return false;
    for (unsigned char c : name) {
        if (!std::isalnum(c) && c != '.' && c != '_' && c != '-') return false;
    }
    return true;
}

#ifdef _WIN32
// A generic credential holds at most CRED_MAX_CREDENTIAL_BLOB_SIZE (2560)
// bytes, and a token can be longer: the first credential holds the number of
// parts and the first part, "<target>#2" on the rest.
constexpr std::size_t kCredPart = 2048;

std::wstring cred_target(const std::string& plugin, const std::string& name, std::size_t part) {
    std::string t = "tapto/plugin/" + plugin + "/" + name;
    if (part > 1) t += "#" + std::to_string(part);
    return widen(t);
}

std::optional<std::string> cred_read(const std::wstring& target) {
    PCREDENTIALW cred = nullptr;
    if (!CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &cred)) return std::nullopt;
    std::string v(reinterpret_cast<const char*>(cred->CredentialBlob), cred->CredentialBlobSize);
    CredFree(cred);
    return v;
}

// The number of parts the secret has now, 0 when there is none.
std::size_t cred_parts(const std::string& plugin, const std::string& name) {
    const auto first = cred_read(cred_target(plugin, name, 1));
    if (!first) return 0;
    const std::size_t nl = first->find('\n');
    return nl == std::string::npos ? 1 : static_cast<std::size_t>(std::atoi(first->c_str()));
}
#else
fs::path secrets_file(const std::string& plugin) {
    return global_dir() / "plugin-secrets" / (plugin + ".json");
}
#endif

} // namespace

std::string store_plugin_secret(const std::string& plugin, const std::string& name,
                                const std::string& value) {
    if (!is_valid_plugin_name(plugin) || !is_valid_secret_name(name))
        return "'" + name + "' is not a secret's name ([A-Za-z0-9._-], at most 64)";
#ifdef _WIN32
    // What was there goes first, so a shorter secret leaves no parts behind.
    const std::size_t old_parts = cred_parts(plugin, name);
    for (std::size_t i = old_parts; i >= 1; --i)
        CredDeleteW(cred_target(plugin, name, i).c_str(), CRED_TYPE_GENERIC, 0);
    if (value.empty()) return "";
    const std::size_t parts = (value.size() + kCredPart - 1) / kCredPart;
    for (std::size_t i = 1; i <= parts; ++i) {
        std::string blob = value.substr((i - 1) * kCredPart, kCredPart);
        if (i == 1) blob = std::to_string(parts) + "\n" + blob;
        const std::wstring target = cred_target(plugin, name, i);
        CREDENTIALW c{};
        c.Type = CRED_TYPE_GENERIC;
        c.TargetName = const_cast<wchar_t*>(target.c_str());
        c.CredentialBlobSize = static_cast<DWORD>(blob.size());
        c.CredentialBlob = reinterpret_cast<LPBYTE>(blob.data());
        c.Persist = CRED_PERSIST_LOCAL_MACHINE;
        std::wstring user = widen(program_name());
        c.UserName = user.data();
        if (!CredWriteW(&c, 0))
            return "Credential Manager refused it (CredWrite error " +
                   std::to_string(GetLastError()) + ")";
    }
    return "";
#else
    const fs::path file = secrets_file(plugin);
    std::error_code ec;
    json all = json::object();
    {
        std::ifstream in(file);
        if (in) {
            all = json::parse(in, nullptr, false);
            if (!all.is_object()) all = json::object();
        }
    }
    if (value.empty()) all.erase(name);
    else all[name] = value;
    fs::create_directories(file.parent_path(), ec);
    fs::permissions(file.parent_path(), fs::perms::owner_all, fs::perm_options::replace, ec);
    // Written beside it, made the user's alone, then put in its place.
    const fs::path tmp = file.string() + ".new";
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out) return "cannot write " + tmp.u8string();
    }
    fs::permissions(tmp, fs::perms::owner_read | fs::perms::owner_write,
                    fs::perm_options::replace, ec);
    {
        std::ofstream out(tmp, std::ios::trunc);
        out << all.dump();
        if (!out) return "cannot write " + tmp.u8string();
    }
    fs::rename(tmp, file, ec);
    if (ec) return "cannot write " + file.u8string() + ": " + ec.message();
    return "";
#endif
}

std::optional<std::string> load_plugin_secret(const std::string& plugin, const std::string& name) {
    if (!is_valid_plugin_name(plugin) || !is_valid_secret_name(name)) return std::nullopt;
#ifdef _WIN32
    const auto first = cred_read(cred_target(plugin, name, 1));
    if (!first) return std::nullopt;
    const std::size_t nl = first->find('\n');
    if (nl == std::string::npos) return first;
    const std::size_t parts = static_cast<std::size_t>(std::atoi(first->c_str()));
    std::string value = first->substr(nl + 1);
    for (std::size_t i = 2; i <= parts; ++i) {
        const auto part = cred_read(cred_target(plugin, name, i));
        if (!part) return std::nullopt; // half a token is none
        value += *part;
    }
    return value;
#else
    std::ifstream in(secrets_file(plugin));
    if (!in) return std::nullopt;
    const json all = json::parse(in, nullptr, false);
    if (!all.is_object() || !all.contains(name) || !all[name].is_string()) return std::nullopt;
    return all[name].get<std::string>();
#endif
}

namespace {

// --- the host a plugin sees ----------------------------------------------------
//
// One per plugin, so its log lines and its calls carry its name. It lives as
// long as the module may call it: until the module is freed, or until exit.

class Host : public ITaptoHost, public ITaptoHostSecrets {
public:
    Host(std::string name, TempFolder* temp) : m_name(std::move(name)), m_temp(temp) {}

    SRESULT SCOM_CALL QueryInterface(const scom::GUID& riid, void** ppv) override {
        if (!ppv) return scom::ERR_BAD_ARGUMENT;
        if (scom::IsEqualGUID(riid, scom::IID_IBase) ||
            scom::IsEqualGUID(riid, IID_ITaptoHost)) {
            *ppv = static_cast<ITaptoHost*>(this);
            return scom::OK;
        }
        if (scom::IsEqualGUID(riid, IID_ITaptoHostSecrets)) {
            *ppv = static_cast<ITaptoHostSecrets*>(this);
            return scom::OK;
        }
        *ppv = nullptr;
        return scom::ERR_NOINTERFACE;
    }
    // Not counted: the Plugins object owns it and outlives the module's use.
    uint32_t SCOM_CALL AddRef() override { return 1; }
    uint32_t SCOM_CALL Release() override { return 1; }

    void* SCOM_CALL MemAlloc(size_t size) override { return mem_alloc(size); }
    void SCOM_CALL MemFree(void* p) override { mem_free(p, m_name); }

    SRESULT SCOM_CALL Log(const char* line) override {
        mclog("[plugin " + m_name + "] " + std::string(line ? line : "") + "\n");
        return scom::OK;
    }

    SRESULT SCOM_CALL IsCancelled() override {
        if (!m_call) return scom::ERR_BAD_CONTEXT;
        return m_call->cancel && m_call->cancel->check() ? scom::OK : scom::ST_FALSE;
    }

    SRESULT SCOM_CALL WriteTemp(const uint8_t* data, size_t size, const char* name_hint,
                                char*& label_path_out) override {
        if (!m_call) return scom::ERR_BAD_CONTEXT;
        if (!data && size) return scom::ERR_BAD_ARGUMENT;
        std::string error;
        const std::string label = temp().write(
            std::string(reinterpret_cast<const char*>(data), size),
            name_hint && *name_hint ? name_hint : m_name, error);
        if (label.empty()) {
            Log(("WriteTemp: " + error).c_str());
            return scom::ERR_NOT_FOUND;
        }
        TaptoString s = TaptoString::copy(label);
        if (!s) return scom::ERR_NO_MEMORY;
        mem_free(label_path_out, m_name); // an inout: the old value is ours to free
        label_path_out = s.detach();
        return scom::OK;
    }

    SRESULT SCOM_CALL AttachImage(const uint8_t* png, size_t size, const char* label) override {
        if (!m_call) return scom::ERR_BAD_CONTEXT;
        // The PNG signature, then IHDR as the first chunk: its width and
        // height are read here, not taken from the plugin.
        static const uint8_t kSig[8] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};
        if (!png || size < 33 || size > kMaxImageBytes || std::memcmp(png, kSig, 8) != 0 ||
            std::memcmp(png + 12, "IHDR", 4) != 0)
            return scom::ERR_BAD_ARGUMENT;
        auto be32 = [](const uint8_t* p) {
            return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) |
                   uint32_t(p[3]);
        };
        const uint32_t w = be32(png + 16), h = be32(png + 20);
        if (w == 0 || h == 0 || w > kMaxImageSide || h > kMaxImageSide)
            return scom::ERR_BAD_ARGUMENT;

        ToolImage image;
        image.png.assign(png, png + size);
        image.width = static_cast<int>(w);
        image.height = static_cast<int>(h);
        image.label = label && *label ? std::string(label)
                      : !m_display.empty() ? m_display
                                           : m_name;
        putToolImage(*m_call, std::move(image));
        return scom::OK;
    }

    // A reference from the plugin's own settings, resolved as a secret config
    // key is. Only while it is being configured, which is when the user's or
    // the policy's settings are what it is reading.
    SRESULT SCOM_CALL ResolveSecret(const char* ref, char*& value_out) override {
        if (!m_configuring && !m_command) return scom::ERR_BAD_CONTEXT;
        const Secret s = resolve_secret(ref ? ref : "");
        TaptoString v = TaptoString::copy(
            s.ok() ? s.value : !s.error.empty() ? s.error : std::string("the secret is empty"));
        if (!v) return scom::ERR_NO_MEMORY;
        mem_free(value_out, m_name); // an inout: the old value is ours to free
        value_out = v.detach();
        return s.ok() ? scom::OK : scom::ERR_NOT_FOUND;
    }

    // Its own secrets, kept between sessions: while it is configured or called.
    SRESULT SCOM_CALL StoreSecret(const char* name, const char* value) override {
        if (!m_configuring && !m_call) return scom::ERR_BAD_CONTEXT;
        const std::string err = store_plugin_secret(m_name, name ? name : "", value ? value : "");
        if (err.empty()) return scom::OK;
        Log(("StoreSecret: " + err).c_str());
        return scom::ERR_BAD_ARGUMENT;
    }
    SRESULT SCOM_CALL LoadSecret(const char* name, char*& value_out) override {
        if (!m_configuring && !m_call) return scom::ERR_BAD_CONTEXT;
        const auto v = load_plugin_secret(m_name, name ? name : "");
        if (!v) return scom::ERR_NOT_FOUND;
        TaptoString s = TaptoString::copy(*v);
        if (!s) return scom::ERR_NO_MEMORY;
        mem_free(value_out, m_name); // an inout: the old value is ours to free
        value_out = s.detach();
        return scom::OK;
    }

    // A Configure in progress: when ResolveSecret answers.
    struct Configuring {
        explicit Configuring(Host& h) : host(h) { host.m_configuring = true; }
        ~Configuring() { host.m_configuring = false; }
        Host& host;
    };
    // A command of the user's in progress (inside a Call): ResolveSecret too.
    struct Commanding {
        explicit Commanding(Host& h) : host(h) { host.m_command = true; }
        ~Commanding() { host.m_command = false; }
        Host& host;
    };

    // The call in progress: what the per-call functions act on.
    struct Call {
        Call(Host& h, Context& c, std::string display) : host(h) {
            host.m_call = &c;
            host.m_display = std::move(display);
        }
        ~Call() {
            host.m_call = nullptr;
            host.m_display.clear();
        }
        Host& host;
    };

    const std::string& name() const { return m_name; }
    // The session's @tmp: the program's, or the process's default one.
    TempFolder& temp() const { return m_temp ? *m_temp : default_temp_folder(); }

private:
    std::string m_name;
    TempFolder* m_temp = nullptr;
    Context* m_call = nullptr;
    bool m_configuring = false;
    bool m_command = false;
    std::string m_display; // the call's first path argument, as the model wrote it
};

// The host's own ITaptoHost, what TaptoString in this module allocates
// through (tapto::plugin_host()).
Host& core_host() {
    static Host h(program_name(), nullptr);
    return h;
}

// --- modules ---------------------------------------------------------------------

struct Module {
#ifdef _WIN32
    HMODULE h = nullptr;
    void* sym(const char* name) const { return reinterpret_cast<void*>(GetProcAddress(h, name)); }
    void close() {
        if (h) FreeLibrary(h);
        h = nullptr;
    }
#else
    void* h = nullptr;
    void* sym(const char* name) const { return dlsym(h, name); }
    void close() {
        if (h) dlclose(h);
        h = nullptr;
    }
#endif
};

#ifdef _WIN32
std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}
#endif

#ifdef TAPTO_PLUGINS_VERIFY
// The SHA-256 of the certificate that signed `file`, after WinVerifyTrust has
// accepted its Authenticode signature. Revocation is not checked: the program
// runs on machines without a route to the CA, and the certificate is pinned
// below, which is the check that matters.
bool signer_hash(const std::wstring& file, HANDLE handle, std::vector<uint8_t>& hash,
                 std::string& error) {
    WINTRUST_FILE_INFO fi{};
    fi.cbStruct = sizeof fi;
    fi.pcwszFilePath = file.c_str();
    fi.hFile = handle;
    WINTRUST_DATA wd{};
    wd.cbStruct = sizeof wd;
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    ::GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG status = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);
    bool ok = false;
    if (status == ERROR_SUCCESS) {
        CRYPT_PROVIDER_DATA* pd = WTHelperProvDataFromStateData(wd.hWVTStateData);
        CRYPT_PROVIDER_SGNR* signer = pd ? WTHelperGetProvSignerFromChain(pd, 0, FALSE, 0) : nullptr;
        if (signer && signer->csCertChain > 0 && signer->pasCertChain[0].pCert) {
            BYTE buf[32];
            DWORD n = sizeof buf;
            if (CertGetCertificateContextProperty(signer->pasCertChain[0].pCert,
                                                  CERT_SHA256_HASH_PROP_ID, buf, &n)) {
                hash.assign(buf, buf + n);
                ok = true;
            }
        }
        if (!ok) error = "its signer's certificate could not be read";
    } else {
        char hex[16];
        std::snprintf(hex, sizeof hex, "0x%08lx", static_cast<unsigned long>(status));
        error = std::string("it has no valid signature (") + hex + ")";
    }
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);
    return ok;
}

// The certificate that signed the program's own executable, the one a plugin must be
// signed with. Empty (and `error`) when this build is not signed.
const std::vector<uint8_t>& own_signer(std::string& error) {
    static std::string own_error;
    static const std::vector<uint8_t> hash = [] {
        std::vector<uint8_t> h;
        wchar_t path[MAX_PATH * 4];
        const DWORD n = GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path)));
        if (n == 0 || n >= std::size(path)) {
            own_error = program_name() + "'s own path could not be read";
            return h;
        }
        if (!signer_hash(path, nullptr, h, own_error)) {
            mclog("[plugins] " + program_name() + " itself: " + own_error + "\n");
            own_error = "this " + program_name() + " build is not signed, so it loads no plugin "
                        "(a Debug build loads unsigned ones)";
        }
        return h;
    }();
    error = own_error;
    return hash;
}
#endif

// Opens `file`, checks it is ours, and loads it. On Windows the file is held
// open, denying writes, from the signature check through the load, so it
// cannot be swapped in between.
bool load_module(const fs::path& given, Module& m, std::string& error) {
    // LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR takes an absolute path only.
    std::error_code ec;
    const fs::path file = fs::absolute(given, ec);
    if (ec) {
        error = "cannot resolve " + given.u8string();
        return false;
    }
#ifdef _WIN32
    const std::wstring wpath = file.wstring();
    HANDLE fh = CreateFileW(wpath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fh == INVALID_HANDLE_VALUE) {
        error = "cannot open " + file.u8string();
        return false;
    }
#  ifdef TAPTO_PLUGINS_VERIFY
    {
        std::string own_error;
        const std::vector<uint8_t>& own = own_signer(own_error);
        std::vector<uint8_t> theirs;
        std::string why;
        if (own.empty()) {
            error = own_error;
        } else if (!signer_hash(wpath, fh, theirs, why)) {
            error = file.filename().u8string() + " is refused: " + why;
        } else if (theirs != own) {
            error = file.filename().u8string() +
                    " is refused: it is signed, but not by the certificate that signed "
                    + program_name();
        }
        if (!error.empty()) {
            CloseHandle(fh);
            return false;
        }
    }
#  else
    mclog("[plugins] loading " + file.u8string() + " without a signature check (Debug build)\n");
#  endif
    // Its own dependencies from its folder and the system's, never from PATH
    // or the working directory.
    m.h = LoadLibraryExW(wpath.c_str(), nullptr,
                         LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    const DWORD gle = GetLastError();
    CloseHandle(fh);
    if (!m.h) {
        error = "cannot load " + file.filename().u8string() + " (error " + std::to_string(gle) + ")";
        return false;
    }
#else
    // The installed directory is root-owned on Linux, which does the job the
    // signature does on Windows.
    m.h = dlopen(file.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!m.h) {
        const char* why = dlerror();
        error = "cannot load " + file.filename().string() + ": " + (why ? why : "dlopen failed");
        return false;
    }
#endif
    return true;
}

} // namespace

// --- a loaded plugin -----------------------------------------------------------

struct Plugins::Loaded {
    struct Tool {
        std::string name;
        std::string description;
        json schema;                          // as the model sees it, marks stripped
        bool writes = false;
        std::vector<std::pair<std::string, bool>> paths; // property, true for "write"
    };

    std::string name;
    std::string version;
    fs::path file;
    bool writable = false;
    std::string fixed_prompt;
    std::vector<std::string> config_keys;
    std::set<std::string> secret_keys;
    std::vector<Tool> tools;
    std::string folder_mode;   // "ro" or "rw" when it declares a folder
    bool folder_per_user = false; // ~/.tapto/plugins/<name>/, not the project's
    std::string folder_key;    // a config key naming the folder instead, or ""
    std::string folder_label;  // "@<name>" once the folder is in the set
    fs::path folder_root;      // the folder as the set holds it

    // Its folder is writable when it says rw and the plugin is loaded rw.
    bool folder_writable() const { return writable && folder_mode == "rw"; }

    // The session's folders and @tmp, as the Plugins object had them when the
    // plugin was added.
    FolderSet* folders = nullptr;
    TempFolder* temp = nullptr;

    Module module;
    CanUnloadNowFn can_unload = nullptr;
    std::unique_ptr<Host> host;
    scom::Ptr<ITaptoPlugin> plugin;
    scom::QIPtr<ITaptoPluginPrompt> prompt;
    scom::QIPtr<ITaptoPluginTools> tool_list; // tools known once configured
    scom::QIPtr<ITaptoPluginCommands> command; // its /<name>, when it declares one
    scom::QIPtr<ITaptoPluginEvents> event_sink; // its events, when it subscribed to any
    std::set<std::string> events;               // those it subscribed to
    std::string command_usage;
    std::string command_description;
    std::string tool_list_text;   // what it last said, to see a change
    bool tools_changed = false;   // a call changed them; see take_tools_changed

    // Shutdown and release, and free the module if it says it can be. When it
    // cannot, the host stays alive for it: `keep_host` is set and the caller
    // keeps this object until exit.
    bool unload() {
        if (plugin) {
            scom::QIPtr<ITaptoPluginUnload> u(plugin.get());
            if (u) u->Shutdown();
            u.Release();
            prompt.Release();
            tool_list.Release();
            command.Release();
            event_sink.Release();
            plugin.Release();
        }
        // Without the exports nothing of it was ever called, so it can go.
        if (module.h && (!can_unload || can_unload() == scom::OK)) {
            module.close();
            return true;
        }
        return !module.h;
    }

    std::string call(const Tool& t, Context& ctx, const json& in) {
        json args = in.is_object() ? in : json::object();
        std::string display;
        for (const auto& [prop, write] : t.paths) {
            if (!args.contains(prop)) continue;
            if (!args[prop].is_string()) return "ERROR: '" + prop + "' must be a path string.";
            fs::path resolved;
            std::string shown, error;
            if (!folders)
                return "ERROR: " + program_name() + " gives the " + name + " plugin no folders, "
                       "so it takes no path.";
            if (!PathRules(*folders).resolve_plugin_path(args[prop].get<std::string>(), write,
                                                         resolved, shown, error))
                return error;
            args[prop] = resolved.u8string();
            if (display.empty()) display = shown;
        }
        const std::string arg_text = args.dump(-1, ' ', false, json::error_handler_t::replace);

        // `t` is one of `tools`, which the call may replace: what is needed of
        // it afterwards is copied first.
        const std::string tool_name = t.name;
        TaptoString out;
        SRESULT r = scom::ERR_BAD_OBJECT;
        {
            Host::Call scope(*host, ctx, display);
            try {
                r = plugin->CallTool(tool_name.c_str(), arg_text.c_str(), out.out());
            } catch (...) {
                // No exception may cross the boundary; one that does from a
                // module built by this compiler is at least reported.
                return "ERROR: the " + name + " plugin failed (an exception escaped " + tool_name +
                       ").";
            }
        }
        reread_tools();
        if (r != scom::OK) {
            return "ERROR: the " + name + " plugin could not make the call (status " +
                   std::to_string(r) + ").";
        }
        return (temp ? *temp : default_temp_folder()).overflow(out.str(), tool_name);
    }

    // After a call: its tools again, from ITaptoPluginTools, when it has that.
    void reread_tools();
};

namespace {

std::string read_tools(const json& list, Plugins::Loaded& l);

// Reads and checks what Describe said; fills `l`. "" when it is fine.
std::string read_description(const std::string& text, Plugins::Loaded& l, bool check_name) {
    const json d = json::parse(text, nullptr, false);
    if (d.is_discarded() || !d.is_object()) return "its description is not a JSON object";
    const std::string name = d.value("name", std::string());
    if (!is_valid_plugin_name(name))
        return "its name '" + name + "' is not one (lowercase letters, digits and '-')";
    if (check_name && name != l.name)
        return "it calls itself '" + name + "', but its file is " + l.file.filename().u8string();
    // @tmp is the core's: a plugin of that name would have its label.
    if (name == "tmp")
        return "its name 'tmp' is reserved (@tmp is " + program_name() + "'s own folder)";
    l.name = name;
    l.version = d.value("version", std::string());
    if (d.contains("prompt") && d["prompt"].is_string()) l.fixed_prompt = d["prompt"];

    if (d.contains("config_keys")) {
        if (!d["config_keys"].is_array()) return "its config_keys is not a list";
        for (const auto& k : d["config_keys"]) {
            const std::string key = k.is_string() ? k.get<std::string>()
                                    : k.is_object() ? k.value("name", std::string())
                                                    : std::string();
            if (key.empty()) return "a config key has no name";
            // The tool-name rule, for keys: a plugin can neither set a core
            // key nor another plugin's, and `config set` finds the plugin
            // from the key (plugin_config_key).
            if (key.rfind(name + "-", 0) != 0 || key.size() == name.size() + 1)
                return "its config key '" + key + "' is not named " + name + "-<something>";
            l.config_keys.push_back(key);
            if (k.is_object() && k.value("secret", false)) l.secret_keys.insert(key);
        }
    }
    if (d.contains("folder")) {
        // "rw", or {"mode": "ro", "scope": "user", "key": "<plugin>-folder"}.
        const json f = d["folder"].is_object() ? d["folder"] : json{{"mode", d["folder"]}};
        const json mode = f.value("mode", json());
        if (mode != "ro" && mode != "rw") return "its folder's mode must be \"ro\" or \"rw\"";
        l.folder_mode = mode.get<std::string>();
        const std::string scope = f.value("scope", std::string("project"));
        if (scope != "project" && scope != "user")
            return "its folder's scope must be \"project\" or \"user\"";
        l.folder_per_user = scope == "user";
        l.folder_key = f.value("key", std::string());
        if (!l.folder_key.empty() &&
            std::find(l.config_keys.begin(), l.config_keys.end(), l.folder_key) ==
                l.config_keys.end())
            return "its folder's key '" + l.folder_key + "' is not one of its config keys";
    }

    if (d.contains("command")) {
        const json& c = d["command"];
        if (!c.is_object() || !c.contains("usage") || !c["usage"].is_string())
            return "its command has no usage";
        l.command_usage = c["usage"];
        l.command_description = c.value("description", std::string());
        // /<name> and nothing else: the tool-name rule, for commands.
        if (l.command_usage.rfind("/" + name, 0) != 0 ||
            (l.command_usage.size() > name.size() + 1 && l.command_usage[name.size() + 1] != ' '))
            return "its command '" + l.command_usage + "' is not /" + name;
    }
    if (d.contains("events")) {
        if (!d["events"].is_array()) return "its events is not a list";
        // An event this host does not have is let be: a newer plugin in an
        // older host is never told of it.
        for (const auto& e : d["events"]) {
            if (!e.is_string()) return "an event it subscribes to is not a name";
            l.events.insert(e.get<std::string>());
        }
    }
    if (!d.contains("tools") || !d["tools"].is_array()) return "it lists no tools";
    return read_tools(d["tools"], l);
}

// Reads and checks a list of tools, Describe's or ITaptoPluginTools'; they
// replace the ones `l` had. "" when it is fine.
std::string read_tools(const json& list, Plugins::Loaded& l) {
    const std::string& name = l.name;
    std::vector<Plugins::Loaded::Tool> tools;
    std::set<std::string> seen;
    for (const auto& t : list) {
        if (!t.is_object()) return "a tool is not an object";
        Plugins::Loaded::Tool tool;
        tool.name = t.value("name", std::string());
        if (tool.name.rfind(name + "_", 0) != 0 || tool.name.size() == name.size() + 1)
            return "its tool '" + tool.name + "' is not named " + name + "_<something>";
        if (!seen.insert(tool.name).second) return "it lists the tool " + tool.name + " twice";
        tool.description = t.value("description", std::string());
        tool.writes = t.value("writes", false);
        tool.schema = t.contains("schema") ? t["schema"] : json{{"type", "object"}};
        if (!tool.schema.is_object()) return tool.name + "'s schema is not an object";
        if (tool.schema.contains("properties") && tool.schema["properties"].is_object()) {
            for (auto& [prop, spec] : tool.schema["properties"].items()) {
                if (!spec.is_object() || !spec.contains("x-tapto-path")) continue;
                const json mark = spec["x-tapto-path"];
                if (mark != "read" && mark != "write")
                    return tool.name + "." + prop + ": x-tapto-path must be \"read\" or \"write\"";
                // A path the plugin writes through is a writing tool, whatever
                // the plugin said.
                if (mark == "write") tool.writes = true;
                tool.paths.emplace_back(prop, mark == "write");
                // Gemini refuses a schema keyword it does not know.
                spec.erase("x-tapto-path");
            }
        }
        tools.push_back(std::move(tool));
    }
    l.tools = std::move(tools);
    return "";
}

// The plugin's config keys, secrets resolved, as Configure takes them.
std::string plugin_config(const Plugins::Loaded& l, std::string& error) {
    json c = json::object();
    for (const auto& key : l.config_keys) {
        auto v = get_effective(key);
        if (!v) continue;
        if (l.secret_keys.count(key)) {
            const Secret s = resolve_secret(*v);
            if (!s.ok()) {
                error = key + ": " + s.error;
                return {};
            }
            c[key] = s.value;
        } else {
            c[key] = *v;
        }
    }
    // "folder", "user_folder" and "program" are no plugin's keys: those are all
    // "<plugin>-...". The user folder is only named: not made, and not in
    // the folder set unless the plugin declares it as its folder.
    c["user_folder"] = plugin_user_folder(l.name).u8string();
    c["program"] = program_name();
    if (!l.folder_label.empty()) {
        c["folder"] = {{"path", l.folder_root.u8string()},
                       {"label", l.folder_label},
                       {"writable", l.folder_writable()}};
    }
    return c.dump();
}

// Configures the plugin with its settings, and then takes its tools from
// ITaptoPluginTools when it has that. "" when it is ready.
std::string configure_plugin(Plugins::Loaded& l) {
    std::string why;
    const std::string cfg = plugin_config(l, why);
    if (!why.empty()) return why;
    {
        Host::Configuring scope(*l.host);
        if (l.plugin->Configure(cfg.c_str()) != scom::OK) return "it refused its configuration";
    }
    if (!l.tool_list) return "";
    TaptoString list;
    json tools;
    if (l.tool_list->Tools(list.out()) == scom::OK) {
        l.tool_list_text = list.str();
        tools = json::parse(l.tool_list_text, nullptr, false);
    }
    if (!tools.is_array()) {
        l.tools.clear();
        return "it gave no list of its tools";
    }
    if (std::string bad = read_tools(tools, l); !bad.empty()) {
        l.tools.clear();
        return bad;
    }
    return "";
}

} // namespace

void Plugins::Loaded::reread_tools() {
    if (!tool_list) return;
    TaptoString list;
    if (tool_list->Tools(list.out()) != scom::OK || list.str() == tool_list_text) return;
    tool_list_text = list.str();
    const json t = json::parse(tool_list_text, nullptr, false);
    std::string bad = t.is_array() ? read_tools(t, *this) : "it gave no list of its tools";
    if (!bad.empty()) {
        mclog("[plugins] " + name + ": its tools after a call: " + bad + "\n");
        tools.clear();
    }
    tools_changed = true;
}

// --- the public side ---------------------------------------------------------------

fs::path plugin_folder(const std::string& name) {
    // The local scope's directory is the project's: the same <encoded-cwd>
    // it keeps its config and saved conversation under.
    const fs::path dir = config_path(Level::Local).parent_path();
    return dir.empty() ? fs::path() : dir / "plugins" / name;
}

fs::path plugin_user_folder(const std::string& name) {
    return global_dir() / "plugins" / name;
}

fs::path plugin_directory_for(const fs::path& exe) {
    const fs::path dir = exe.parent_path();
#ifndef _WIN32
    // Installed, the executable is in a bin directory (/usr/bin from the
    // packages), and modules do not belong there: they go in the program's own
    // directory under lib, named after it: /usr/lib/tapto-code/plugins.
    if (dir.filename() == "bin") return dir.parent_path() / "lib" / exe.stem() / "plugins";
#endif
    return dir / "plugins";
}

fs::path plugin_directory() {
#ifdef _WIN32
    wchar_t path[MAX_PATH * 4];
    const DWORD n = GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path)));
    if (n == 0 || n >= std::size(path)) return {};
    return plugin_directory_for(fs::path(path));
#elif defined(__APPLE__)
    char buf[4096];
    uint32_t size = sizeof buf;
    if (_NSGetExecutablePath(buf, &size) != 0) return {};
    std::error_code ec;
    return plugin_directory_for(fs::canonical(buf, ec));
#else
    std::error_code ec;
    const fs::path exe = fs::read_symlink("/proc/self/exe", ec);
    if (ec) return {};
    return plugin_directory_for(exe);
#endif
}

std::vector<std::string> available_plugins() {
    std::vector<std::string> names;
    const fs::path dir = plugin_directory();
    std::error_code ec;
    for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
        const fs::path& p = it->path();
        if (p.extension() != kModuleExt) continue;
        const std::string stem = p.stem().u8string();
        if (is_valid_plugin_name(stem)) names.push_back(stem);
    }
    std::sort(names.begin(), names.end());
    return names;
}

std::string plugin_of_key(const std::string& key) {
    static const std::string kPrefix = "plugin.";
    return key.rfind(kPrefix, 0) == 0 ? key.substr(kPrefix.size()) : std::string();
}

std::optional<PluginMode> parse_plugin_mode(const std::string& value) {
    const std::string v = trim(value);
    if (v == "ro") return PluginMode::Ro;
    if (v == "rw") return PluginMode::Rw;
    if (v == "off") return PluginMode::Off;
    return std::nullopt;
}

std::string plugin_policy_refusal(const std::string& name, bool by_policy,
                                  const std::vector<Config::Entry>& policy) {
    auto find = [&](const char* key) -> const std::string* {
        for (const auto& e : policy) {
            if (e.first == key) return &e.second;
        }
        return nullptr;
    };
    if (const std::string* allowed = find("allowed-plugins")) {
        const auto names = split_list(*allowed);
        if (std::find(names.begin(), names.end(), name) == names.end()) {
            std::string list;
            for (const auto& n : names) list += (list.empty() ? "" : ", ") + n;
            return "your organization's policy allows only these plugins: " +
                   (list.empty() ? std::string("none") : list);
        }
    }
    if (!by_policy) {
        if (const std::string* user = find("allow-user-plugins"); user && is_false(*user))
            return "your organization's policy loads only the plugins it names itself "
                   "(its plugin." + name + " setting)";
    }
    return "";
}

Plugins::Plugins(FolderSet* folders) : m_folders(folders) {
    if (!plugin_host()) plugin_host() = &core_host();
}

namespace {

// Puts the plugin's folder in `folders` as @<name>. The folder its key names
// must be there already; the default one is made when it is not. "" on
// success.
std::string add_folder(Plugins::Loaded& p, FolderSet* folders) {
    if (!folders) return "it wants a folder, and this " + program_name() + " has none to give";
    std::error_code ec;
    fs::path dir;
    if (auto set = p.folder_key.empty() ? std::nullopt : get_effective(p.folder_key)) {
        // A setting, perhaps the policy's: the user's or the admin's own
        // folder, which is never made here.
        dir = fs::u8path(*set);
        if (!dir.is_absolute())
            return p.folder_key + " must be an absolute path, not " + *set;
        if (!fs::is_directory(dir, ec))
            return p.folder_key + " names " + *set + ", which is not a folder";
    } else {
        dir = p.folder_per_user ? plugin_user_folder(p.name) : plugin_folder(p.name);
        if (dir.empty())
            return "it wants a folder, and there is no project (the working directory "
                   "could not be read)";
        fs::create_directories(dir, ec);
        if (ec) return "cannot make its folder " + dir.u8string() + ": " + ec.message();
    }
    const std::string label = "@" + p.name;
    const std::string err = folders->add_system(label, dir.u8string(), p.folder_writable(),
                                                "the " + p.name + " plugin's folder");
    if (!err.empty()) return err.rfind("ERROR: ", 0) == 0 ? err.substr(7) : err;
    p.folder_label = label;
    p.folder_root = folders->get(label)->root;
    return "";
}

// Asks the loaded module for its plugin, reads its description and, when
// `configure`, gives it its folder and configures it. "" when it is ready to
// offer its tools; on failure its folder is gone again.
std::string attach(Plugins::Loaded& p, bool check_name, bool configure = true,
                   FolderSet* folders = nullptr) {
    auto get = reinterpret_cast<GetPluginFn>(p.module.sym(kGetPluginExport));
    p.can_unload = reinterpret_cast<CanUnloadNowFn>(p.module.sym(kCanUnloadNowExport));
    if (!get || !p.can_unload)
        return p.file.filename().u8string() + " is not a tapto plugin (it has no " +
               kGetPluginExport + " or " + kCanUnloadNowExport + ")";
    p.host = std::make_unique<Host>(p.name.empty() ? p.file.stem().u8string() : p.name, p.temp);
    void* pv = nullptr;
    const SRESULT r = get(p.host.get(), IID_ITaptoPlugin, &pv);
    if (r != scom::OK || !pv)
        return p.file.filename().u8string() + " gave no plugin (status " + std::to_string(r) + ")";
    p.plugin.Attach(static_cast<ITaptoPlugin*>(pv));
    TaptoString desc;
    if (p.plugin->Describe(desc.out()) != scom::OK) return "its Describe failed";
    if (std::string why = read_description(desc.str(), p, check_name); !why.empty()) return why;
    if (!configure) return "";
    if (!p.folder_mode.empty()) {
        if (std::string why = add_folder(p, folders); !why.empty()) return why;
    }
    p.tool_list = scom::QIPtr<ITaptoPluginTools>(p.plugin.get());
    if (std::string why = configure_plugin(p); !why.empty()) {
        if (!p.folder_label.empty()) folders->remove_system(p.folder_label);
        p.folder_label.clear();
        return why;
    }
    p.prompt = scom::QIPtr<ITaptoPluginPrompt>(p.plugin.get());
    if (!p.events.empty()) {
        p.event_sink = scom::QIPtr<ITaptoPluginEvents>(p.plugin.get());
        if (!p.event_sink) {
            if (!p.folder_label.empty()) folders->remove_system(p.folder_label);
            p.folder_label.clear();
            return "it subscribes to events, but cannot take them";
        }
    }
    if (!p.command_usage.empty()) {
        p.command = scom::QIPtr<ITaptoPluginCommands>(p.plugin.get());
        if (!p.command) {
            if (!p.folder_label.empty()) folders->remove_system(p.folder_label);
            p.folder_label.clear();
            return "it declares a command, but cannot run one";
        }
    }
    return "";
}

// Unloads `l` for good, or, when its module cannot be freed, leaves the
// module and its host to the end of the process.
void finish(std::unique_ptr<Plugins::Loaded>& l) {
    if (!l->unload()) {
        (void)l->host.release();
        l->module.h = nullptr;
    }
}

} // namespace

std::optional<PluginConfigKey> plugin_config_key(const std::string& key, std::string& why,
                                                 const fs::path& dir) {
    if (!plugin_host()) plugin_host() = &core_host();
    // A plugin name may itself contain '-', so each prefix is a candidate:
    // "my-plugin-url" is my's key or my-plugin's.
    for (std::size_t dash = key.find('-'); dash != std::string::npos;
         dash = key.find('-', dash + 1)) {
        const std::string name = key.substr(0, dash);
        if (dash + 1 == key.size() || !is_valid_plugin_name(name)) continue;
        const fs::path file = dir / (name + kModuleExt);
        std::error_code ec;
        if (!fs::is_regular_file(file, ec)) continue;
        // allowed-plugins applies; allow-user-plugins does not, since the
        // policy's own `plugins` may load it and still leave its keys to the
        // user.
        if (std::string refusal = plugin_policy_refusal(name, /*by_policy=*/true, policy_entries());
            !refusal.empty()) {
            why = "the " + name + " plugin is not allowed: " + refusal;
            continue;
        }
        auto l = std::make_unique<Plugins::Loaded>();
        l->name = name;
        l->file = file;
        std::string error;
        if (!load_module(file, l->module, error)) {
            why = error;
            continue;
        }
        const std::string bad = attach(*l, /*check_name=*/true, /*configure=*/false);
        std::optional<PluginConfigKey> found;
        if (!bad.empty()) {
            why = "plugin '" + name + "': " + bad;
        } else if (std::find(l->config_keys.begin(), l->config_keys.end(), key) !=
                   l->config_keys.end()) {
            found = PluginConfigKey{name, l->secret_keys.count(key) > 0};
        } else {
            std::string keys;
            for (const auto& k : l->config_keys) keys += (keys.empty() ? "" : ", ") + k;
            why = "the " + name + " plugin has no key '" + key + "' (its keys: " +
                  (keys.empty() ? std::string("none") : keys) + ")";
        }
        finish(l);
        if (found) return found;
    }
    return std::nullopt;
}

Plugins::~Plugins() {
    for (auto& l : m_loaded) finish(l);
    for (auto& l : m_hidden) finish(l);
}

std::string Plugins::add(const std::string& name, bool writable, bool by_policy) {
    if (!is_valid_plugin_name(name))
        return "'" + name + "' is not a plugin name (lowercase letters, digits and '-')";
    const auto policy = policy_entries();
    for (auto& l : m_loaded) {
        if (l->name != name) continue;
        if (l->writable == writable) return "";
        if (std::string why = plugin_policy_refusal(name, by_policy, policy); !why.empty())
            return why;
        l->writable = writable;
        // Its folder follows the mode, and the plugin is told, so what it
        // says of the folder stays true.
        if (!l->folder_label.empty() && m_folders) {
            m_folders->set_system_writable(l->folder_label, l->folder_writable());
            if (std::string why = configure_plugin(*l); !why.empty())
                mclog("[plugins] " + name + ": " + why + "\n");
        }
        return "";
    }
    if (std::string why = plugin_policy_refusal(name, by_policy, policy); !why.empty())
        return why;
    const fs::path file = plugin_directory() / (name + kModuleExt);
    std::error_code ec;
    if (!fs::is_regular_file(file, ec)) {
        std::string list;
        for (const auto& n : available_plugins()) list += (list.empty() ? "" : ", ") + n;
        return "there is no plugin '" + name + "' in " + plugin_directory().u8string() +
               (list.empty() ? std::string(" (none is installed)") : " (installed: " + list + ")");
    }
    auto l = std::make_unique<Loaded>();
    l->name = name;
    l->file = file;
    l->writable = writable;
    l->folders = m_folders;
    l->temp = m_temp;
    std::string error;
    if (!load_module(file, l->module, error)) return error;
    if (std::string why = attach(*l, /*check_name=*/true, /*configure=*/true, m_folders);
        !why.empty()) {
        finish(l);
        return "plugin '" + name + "': " + why;
    }
    mclog("[plugins] loaded " + name + " " + l->version + " (" + (writable ? "rw" : "ro") +
          ") from " + file.u8string() + "\n");
    m_loaded.push_back(std::move(l));
    return "";
}

std::string Plugins::add_file(const fs::path& file, bool writable) {
    auto l = std::make_unique<Loaded>();
    l->file = file;
    l->writable = writable;
    l->folders = m_folders;
    l->temp = m_temp;
    std::string error;
    if (!load_module(file, l->module, error)) return error;
    if (std::string why = attach(*l, /*check_name=*/false, /*configure=*/true, m_folders);
        !why.empty()) {
        finish(l);
        return file.filename().u8string() + ": " + why;
    }
    for (const auto& have : m_loaded) {
        if (have->name == l->name) {
            finish(l);
            return "a plugin named '" + have->name + "' is loaded already";
        }
    }
    m_loaded.push_back(std::move(l));
    return "";
}

bool Plugins::remove(const std::string& name, bool* unloaded) {
    auto it = std::find_if(m_loaded.begin(), m_loaded.end(),
                           [&](const auto& l) { return l->name == name; });
    if (it == m_loaded.end()) return false;
    std::unique_ptr<Loaded> l = std::move(*it);
    m_loaded.erase(it);
    if (!l->folder_label.empty() && m_folders) m_folders->remove_system(l->folder_label);
    const bool freed = l->unload();
    if (unloaded) *unloaded = freed;
    // Not freed: it stays loaded with its tools gone, and its host with it.
    if (!freed) m_hidden.push_back(std::move(l));
    mclog("[plugins] removed " + name + (freed ? ", module freed\n" : ", module kept until exit\n"));
    return true;
}

std::vector<ToolSpec> Plugins::tools() const {
    std::vector<ToolSpec> out;
    for (const auto& lp : m_loaded) {
        Loaded* l = lp.get();
        for (const Loaded::Tool& t : l->tools) {
            // A writing tool is not refused when called: it is never offered.
            if (t.writes && !l->writable) continue;
            ToolSpec spec;
            spec.name = t.name;
            spec.description = t.description;
            spec.parameters = t.schema;
            // By name: a call may replace the plugin's tools under a turn
            // that still holds these, and a tool that has gone says so.
            spec.executor = [l, name = t.name](Context& ctx, const json& in) -> std::string {
                for (const auto& now : l->tools) {
                    if (now.name != name) continue;
                    if (now.writes && !l->writable) break;
                    return l->call(now, ctx, in);
                }
                return "ERROR: the " + l->name + " plugin no longer offers " + name + ".";
            };
            out.push_back(std::move(spec));
        }
    }
    return out;
}

std::string Plugins::prompt() const {
    std::string out;
    for (const auto& l : m_loaded) {
        std::string text = l->fixed_prompt;
        if (l->prompt) {
            TaptoString changing;
            if (l->prompt->Prompt(changing.out()) == scom::OK && !changing.empty())
                text += (text.empty() ? "" : "\n\n") + changing.str();
        }
        if (!text.empty()) out += (out.empty() ? "" : "\n\n") + text;
    }
    return out;
}

std::string Plugins::before_turn(Context& ctx, bool& changed) {
    std::string text;
    for (auto& l : m_loaded) {
        if (!l->event_sink || !l->events.count("before_turn")) continue;
        TaptoString out;
        SRESULT r = scom::ST_FALSE;
        {
            // As a command is run: it reads the user's settings at their word.
            Host::Call scope(*l->host, ctx, "");
            Host::Commanding commanding(*l->host);
            try {
                r = l->event_sink->OnEvent("before_turn", "{}", out.out());
            } catch (...) {
                mclog("[plugins] " + l->name + ": an exception escaped its before_turn\n");
            }
        }
        if (!out.empty()) text += (text.empty() ? "" : "\n") + out.str();
        if (r != scom::OK) continue;
        l->reread_tools();
        l->tools_changed = false;
        changed = true;
    }
    return text;
}

std::vector<Plugins::Command> Plugins::commands() const {
    std::vector<Command> out;
    for (const auto& l : m_loaded) {
        if (l->command) out.push_back({l->name, l->command_usage, l->command_description});
    }
    return out;
}

std::optional<std::string> Plugins::run_command(const std::string& name, const std::string& args,
                                                Context& ctx) {
    for (auto& l : m_loaded) {
        if (l->name != name || !l->command) continue;
        TaptoString out;
        SRESULT r = scom::ERR_BAD_OBJECT;
        {
            Host::Call scope(*l->host, ctx, "");
            Host::Commanding commanding(*l->host);
            try {
                r = l->command->RunCommand(args.c_str(), out.out());
            } catch (...) {
                return "the " + name + " plugin failed (an exception escaped its command)";
            }
        }
        l->reread_tools();
        l->tools_changed = false; // the caller rebuilds after a command anyway
        if (r != scom::OK)
            return "the " + name + " plugin could not run the command (status " + std::to_string(r) + ")";
        return out.str();
    }
    return std::nullopt;
}

bool Plugins::take_tools_changed() {
    bool changed = false;
    for (auto& l : m_loaded) {
        changed = changed || l->tools_changed;
        l->tools_changed = false;
    }
    return changed;
}

std::vector<Plugins::Entry> Plugins::loaded() const {
    std::vector<Entry> out;
    for (const auto& l : m_loaded) {
        Entry e;
        e.name = l->name;
        e.version = l->version;
        e.writable = l->writable;
        e.tools = l->tools.size();
        e.write_tools = static_cast<std::size_t>(std::count_if(
            l->tools.begin(), l->tools.end(), [](const auto& t) { return t.writes; }));
        e.file = l->file;
        e.folder = l->folder_label;
        out.push_back(std::move(e));
    }
    return out;
}

} // namespace tapto

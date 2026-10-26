// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#pragma once

// sCom: the shell-extension style of COM, vendored from cpr (the Centlake
// Portable Runtime), include/cpr/com.h at cpr commit ecfd6e6. A module hands
// out objects through interfaces of pure virtual functions, found by GUID
// with QueryInterface and kept alive by AddRef/Release.
//
// This is the plugin boundary of the tapto programs (see tapto/plugin.h), so
// what matters is the binary layout, and that is cpr's: a 16-byte GUID, the
// IBase vtable (QueryInterface, AddRef, Release) and 32-bit status codes. An
// object built against cpr's com.h can be handed to this header and the other
// way round. What changed on the way in:
//
//  - Types from <cstdint> in place of cpr's LONG/ULONG/USHORT/UCHAR, which
//    cpr already makes fixed-width on both platforms, so nothing moves.
//  - C_API is SCOM_CALL: __stdcall on Windows, empty elsewhere. Only 32-bit
//    x86 has more than one calling convention; it is kept so a win32 build
//    still matches cpr's modules.
//  - Status codes are constexpr in this namespace, not #define OK 0, so the
//    header does not define OK for every file that includes it.
//  - No `interface` macro (windows.h has its own); interfaces are structs,
//    which is what it expanded to.
//  - GUID is scom::GUID, always defined here, rather than whichever of
//    windows.h's and this one a translation unit happened to see first. The
//    layout is the same.
//  - An interface's IID is found by an overload, scom_iid_of(T*), which
//    SCOM_DEFINE_IID declares beside the interface in any namespace, in place
//    of cpr's trait specialisation that had to be in cpr's own.
//  - Only what the plugin system uses: no string or buffer functions (the
//    plugin host allocates, see ITaptoHost), no IPC codes, no type info.

#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <memory>

#if defined(_WIN32) && !defined(_WIN64)
#  define SCOM_CALL __stdcall
#else
#  define SCOM_CALL
#endif

namespace scom {

using SRESULT = int32_t;

// cpr's values, so a status from a cpr module means the same here.
constexpr SRESULT OK = 0;
constexpr SRESULT ST_FALSE = 1;           // false, not an error
constexpr SRESULT ST_NO_MORE = 2;         // ends an iteration
constexpr SRESULT ST_NOT_FOUND = 3;       // object not found
constexpr SRESULT ERR_NOINTERFACE = 100;  // the object has no such interface
constexpr SRESULT ERR_NOT_FOUND = 102;    // the requested data was not found
constexpr SRESULT ERR_BAD_ARGUMENT = 106; // an argument is wrong
constexpr SRESULT ERR_NO_MEMORY = 107;    // an allocation failed
constexpr SRESULT ERR_BAD_OBJECT = 113;
constexpr SRESULT ERR_BAD_CONTEXT = 117;  // not callable in this state

inline bool succeeded(SRESULT r) { return r == OK || r == ST_FALSE; }

struct GUID {
    uint32_t Data1;
    uint16_t Data2;
    uint16_t Data3;
    uint8_t Data4[8];
};
static_assert(sizeof(GUID) == 16, "GUID must stay 16 bytes");

inline bool IsEqualGUID(const GUID& a, const GUID& b) {
    return std::memcmp(&a, &b, sizeof(GUID)) == 0;
}

struct IBase {
    virtual SRESULT SCOM_CALL QueryInterface(const GUID& riid, void** ppv) = 0;
    virtual uint32_t SCOM_CALL AddRef() = 0;
    virtual uint32_t SCOM_CALL Release() = 0;
};

// Declares IID_<Iface> and the scom_iid_of overload that the interface map
// and the smart pointers find it by. At namespace scope, in the interface's
// own namespace:
//
//   struct IFoo : scom::IBase { ... };
//   SCOM_DEFINE_IID(IFoo, 0x12345678, 0x1234, 0x1234, 0x12, 0x34, ...);
#define SCOM_DEFINE_IID(Iface, x, s1, s2, c1, c2, c3, c4, c5, c6, c7, c8)    \
    inline constexpr ::scom::GUID IID_##Iface = {                            \
        x, s1, s2, {c1, c2, c3, c4, c5, c6, c7, c8}};                        \
    constexpr const ::scom::GUID& scom_iid_of(Iface*) { return IID_##Iface; }

// {66BDC8A2-87D0-4459-AFF0-2BE7481025A5}, as in cpr.
SCOM_DEFINE_IID(IBase, 0x66bdc8a2, 0x87d0, 0x4459, 0xaf, 0xf0, 0x2b, 0xe7, 0x48, 0x10,
                0x25, 0xa5)

template <class T>
constexpr const GUID& iid_of() {
    return scom_iid_of(static_cast<T*>(nullptr));
}

// --- implementing an object -------------------------------------------------
//
//   class Foo : public scom::Base, public IFoo, public IBar {
//   public:
//       SCOM_IMPLEMENT_BASE_EX(Foo, IFoo)
//       SCOM_BEGIN_INTERFACE_MAP(Foo)
//           SCOM_INTERFACE(IFoo)
//           SCOM_INTERFACE(IBar)
//       SCOM_END_INTERFACE_MAP()
//       ...
//   };
//
// A new object starts at one reference, owned by whoever created it.

#define SCOM_BEGIN_INTERFACE_MAP(x)                                              \
    ::scom::SRESULT _scomQueryInterface(const ::scom::GUID& riid, void** ppv) {

#define SCOM_INTERFACE(t)                                                        \
    if (::scom::IsEqualGUID(riid, ::scom::iid_of<t>())) {                        \
        *ppv = static_cast<t*>(this);                                            \
        AddRef();                                                                \
        return ::scom::OK;                                                       \
    }

#define SCOM_END_INTERFACE_MAP()                                                 \
    *ppv = nullptr;                                                              \
    return ::scom::ERR_NOINTERFACE;                                              \
    }

class Base {
public:
    Base() : m_ref(1) {}

protected:
    ~Base() = default;
    std::atomic<int32_t> m_ref;
};

#define SCOM_IMPLEMENT_BASE_EX(obj, baseIfc)                                     \
    ::scom::SRESULT SCOM_CALL QueryInterface(const ::scom::GUID& riid,           \
                                             void** ppv) override {              \
        if (!ppv) return ::scom::ERR_BAD_ARGUMENT;                               \
        if (::scom::IsEqualGUID(riid, ::scom::IID_IBase)) {                      \
            *ppv = static_cast<::scom::IBase*>(static_cast<baseIfc*>(this));     \
            AddRef();                                                            \
            return ::scom::OK;                                                   \
        }                                                                        \
        /* Undefined? SCOM_BEGIN_INTERFACE_MAP is missing. */                    \
        return _scomQueryInterface(riid, ppv);                                   \
    }                                                                            \
    uint32_t SCOM_CALL AddRef() override {                                       \
        assert(m_ref != 0);                                                      \
        return static_cast<uint32_t>(++m_ref);                                   \
    }                                                                            \
    uint32_t SCOM_CALL Release() override {                                      \
        const int32_t t = --m_ref;                                               \
        if (t != 0) return static_cast<uint32_t>(t);                             \
        delete this;                                                             \
        return 0;                                                                \
    }

#define SCOM_IMPLEMENT_BASE(obj) SCOM_IMPLEMENT_BASE_EX(obj, ::scom::IBase)

// An object that lives as long as its module (a static), so it does not count
// references. The host's own ITaptoHost is one.
template <class T>
class Global : public T {
public:
    SRESULT SCOM_CALL QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return ERR_BAD_ARGUMENT;
        if (IsEqualGUID(riid, IID_IBase)) {
            *ppv = static_cast<IBase*>(this);
            return OK;
        }
        // Undefined? SCOM_BEGIN_INTERFACE_MAP is missing.
        return T::_scomQueryInterface(riid, ppv);
    }
    uint32_t SCOM_CALL AddRef() override { return 1; }
    uint32_t SCOM_CALL Release() override { return 1; }
};

// --- holding a pointer --------------------------------------------------------

// What -> returns: the interface with AddRef and Release out of reach, so the
// smart pointer's count is the only one that moves.
template <class T>
class ProtectRef : public T {
private:
    uint32_t SCOM_CALL AddRef() override = 0;
    uint32_t SCOM_CALL Release() override = 0;
};

template <class T>
class Ptr {
public:
    Ptr() = default;
    Ptr(T* p) : m_p(p) {
        if (m_p) m_p->AddRef();
    }
    Ptr(const Ptr& o) : Ptr(o.m_p) {}
    Ptr(Ptr&& o) noexcept : m_p(o.m_p) { o.m_p = nullptr; }
    ~Ptr() { Release(); }

    Ptr& operator=(T* p) {
        if (p) p->AddRef();
        T* old = m_p;
        m_p = p;
        if (old) old->Release();
        return *this;
    }
    Ptr& operator=(const Ptr& o) { return *this = o.m_p; }
    Ptr& operator=(Ptr&& o) noexcept {
        if (this != std::addressof(o)) { // & is overloaded, for out parameters
            Release();
            m_p = o.m_p;
            o.m_p = nullptr;
        }
        return *this;
    }

    void Release() {
        if (T* t = m_p) {
            m_p = nullptr;
            t->Release();
        }
    }
    // Takes over a reference the caller already owns, without an AddRef.
    void Attach(T* p) {
        Release();
        m_p = p;
    }
    T* Detach() {
        T* t = m_p;
        m_p = nullptr;
        return t;
    }

    operator T*() const { return m_p; }
    T* get() const { return m_p; }
    T& operator*() const {
        assert(m_p);
        return *m_p;
    }
    ProtectRef<T>* operator->() const {
        assert(m_p);
        return static_cast<ProtectRef<T>*>(m_p);
    }
    // For an out parameter: must be empty, so no reference leaks.
    T** operator&() {
        assert(!m_p);
        return &m_p;
    }
    bool operator!() const { return !m_p; }

    template <class Q>
    SRESULT QueryInterface(Q** pp) const {
        assert(pp && !*pp);
        return m_p->QueryInterface(iid_of<Q>(), reinterpret_cast<void**>(pp));
    }

private:
    T* m_p = nullptr;
};

// A Ptr<T> filled by QueryInterface from any interface of the same object;
// empty when the object does not have T.
template <class T>
class QIPtr : public Ptr<T> {
public:
    QIPtr() = default;
    explicit QIPtr(IBase* p) {
        if (!p) return;
        T* q = nullptr;
        if (p->QueryInterface(iid_of<T>(), reinterpret_cast<void**>(&q)) == OK)
            this->Attach(q);
    }
};

} // namespace scom

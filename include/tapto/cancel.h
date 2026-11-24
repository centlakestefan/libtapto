// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#pragma once
#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>

// Cancellation token for interrupting the model's tool loop. The checkpoint
// in the loop calls check(), which non-blockingly polls for the interrupt
// signal (e.g. an ESC keypress) and reports whether the loop should stop.
//
// No background thread is needed: the poll happens in the same thread that
// runs the tool loop, at each loop iteration. Between checkpoints the thread
// is blocked on an HTTP call or tool execution, and there is nothing we can
// do to interrupt those anyway.
//
// A program that does watch the keyboard on a thread of its own can do more:
// it calls cancel() from there, and what blocks the turn's thread registers
// an AbortHook with what stops it -- run_command its process -- so ESC takes
// effect while a build is still running, not when it is done. A program
// without such a thread polls through check() as before.
//
// m_cancelled / m_check_fn are mutable so check() can be const: the backends
// reach the token through Context's const CancellationToken* and must be able
// to test (and latch) cancellation without a non-const handle.
class CancellationToken {
public:
    // Call at each loop checkpoint. Returns true if cancelled.
    // The poll runs at every checkpoint (not just before cancellation) so that
    // after the fact it keeps draining pending input, and no stray ESC bytes
    // left in the queue leak into the next user prompt.
    bool check() const {
        if (m_check_fn && m_check_fn())
            m_cancelled.store(true, std::memory_order_release);
        return m_cancelled.load(std::memory_order_acquire);
    }

    bool cancelled() const { return m_cancelled.load(std::memory_order_acquire); }
    void reset() { m_cancelled.store(false, std::memory_order_release); }

    // Install the non-blocking input poll. Returns true if the interrupt key
    // (ESC) was detected; other pending input is consumed and discarded.
    void setCheckFn(std::function<bool()> fn) { m_check_fn = std::move(fn); }

    // Cancel, from any thread, and run every abort hook registered now, so
    // what the turn is blocked in stops rather than runs to its end. Calling
    // it again runs them again, which lets a hook escalate (a command asked
    // to stop, then killed).
    void cancel() const {
        m_cancelled.store(true, std::memory_order_release);
        std::lock_guard<std::mutex> lock(m_hooks_mutex);
        for (auto& hook : m_hooks) hook.second();
    }

    // An abort hook for as long as it lives, registered by whatever blocks the
    // turn's thread with what stops it. It runs on the thread that calls
    // cancel(), never after its destructor has returned, and at once when the
    // token is cancelled already. A null token registers nothing.
    class AbortHook {
    public:
        AbortHook(const CancellationToken* token, std::function<void()> fn) : m_token(token) {
            if (!m_token) return;
            std::lock_guard<std::mutex> lock(m_token->m_hooks_mutex);
            m_id = ++m_token->m_next_hook;
            auto& hook = m_token->m_hooks[m_id];
            hook = std::move(fn);
            if (m_token->cancelled()) hook();
        }
        ~AbortHook() {
            if (!m_token) return;
            std::lock_guard<std::mutex> lock(m_token->m_hooks_mutex);
            m_token->m_hooks.erase(m_id);
        }
        AbortHook(const AbortHook&) = delete;
        AbortHook& operator=(const AbortHook&) = delete;

    private:
        const CancellationToken* m_token;
        std::uint64_t m_id = 0;
    };

private:
    mutable std::atomic<bool>  m_cancelled{false};
    mutable std::function<bool()> m_check_fn;
    mutable std::mutex m_hooks_mutex;
    mutable std::map<std::uint64_t, std::function<void()>> m_hooks;
    mutable std::uint64_t m_next_hook = 0;
};

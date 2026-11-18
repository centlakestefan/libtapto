// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#include "tapto/retry.h"

#include "tapto/cancel.h"

#include <algorithm>
#include <thread>

namespace tapto {

RetryBudget::RetryBudget(int max_retries, int base_seconds, int max_wait_seconds, int retry_for_seconds)
    : m_max(max_retries), m_base(std::max(1, base_seconds)), m_maxWait(std::max(1, max_wait_seconds)),
      m_retryFor(std::max(0, retry_for_seconds)) {}

bool RetryBudget::next(int hint_seconds) {
    const auto now = std::chrono::steady_clock::now();
    if (m_retries == 0) m_first = now;
    if (m_retryFor > 0) {
        if (elapsed_seconds() >= m_retryFor) return false;
    } else if (m_retries >= m_max) {
        return false;
    }
    ++m_retries;
    // shift clamped so a long run of retries cannot overflow it
    int wait = hint_seconds > 0 ? hint_seconds : m_base * (1 << std::min(m_retries - 1, 16));
    wait = std::min(wait, m_maxWait);
    // the last wait ends at the time given, not past it
    if (m_retryFor > 0) wait = std::max(1, std::min(wait, m_retryFor - elapsed_seconds()));
    m_wait = wait;
    return true;
}

void RetryBudget::reset() {
    m_retries = 0;
    m_wait = 0;
}

int RetryBudget::elapsed_seconds() const {
    if (m_retries == 0) return 0;
    return static_cast<int>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - m_first).count());
}

std::string RetryBudget::spent() const {
    std::string s = std::to_string(m_retries) + (m_retries == 1 ? " retry" : " retries");
    if (m_retryFor > 0) s += " in " + std::to_string(elapsed_seconds()) + " s";
    return s;
}

bool retry_wait(int seconds, const CancellationToken* cancel) {
    const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(std::max(0, seconds));
    for (;;) {
        if (cancel && cancel->check()) return false;
        const auto now = std::chrono::steady_clock::now();
        if (now >= until) return true;
        std::this_thread::sleep_for(std::min<std::chrono::steady_clock::duration>(
            until - now, std::chrono::milliseconds(200)));
    }
}

} // namespace tapto

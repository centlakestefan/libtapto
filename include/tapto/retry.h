// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#pragma once

#include <chrono>
#include <string>

class CancellationToken;

namespace tapto {

// One request's retries of one kind of failure (the connection, a server
// error, rate limiting): how many so far, the wait before the next, and when
// to give up.
//
// Counted, it gives up after max_retries. With a time to keep at it
// (AiConfig::setRetryForSeconds) it gives up only once that long has passed
// since the first failure, so an AI server that is gone for minutes -- a
// restart, a model reloading, a switch's software upgrade -- is waited out
// rather than counted out in the minute five doubling waits add up to.
class RetryBudget {
public:
    RetryBudget(int max_retries, int base_seconds, int max_wait_seconds, int retry_for_seconds = 0);

    // Another retry, waiting the server's hint (retry-after) when it gave one
    // or else the next of the doubling waits, both at most max_wait_seconds.
    // False: spent.
    bool next(int hint_seconds = 0);

    // The connection came back: the next failure of it starts over.
    void reset();

    int retry() const { return m_retries; }              // 1 for the first
    int wait_seconds() const { return m_wait; }          // before this retry
    int max_retries() const { return m_retryFor > 0 ? 0 : m_max; } // 0: until retry_for
    int retry_for() const { return m_retryFor; }
    int elapsed_seconds() const;                          // since the first failure

    // How the request gave up: "5 retries", "41 retries in 3605 s".
    std::string spent() const;

private:
    int m_max;
    int m_base;
    int m_maxWait;
    int m_retryFor;
    int m_retries = 0;
    int m_wait = 0;
    std::chrono::steady_clock::time_point m_first;
};

// Waits `seconds`, looking at the token as it goes, so a stop (ESC, a task
// cancelled, a server shutting down) does not sit out the wait. False: it
// said stop.
bool retry_wait(int seconds, const CancellationToken* cancel);

} // namespace tapto

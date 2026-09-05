// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

#pragma once

#include <optional>
#include <string>
#include <vector>

#include "tapto/paths.h"
#include "tapto/secret.h"

// ---------------------------------------------------------------------------
// Provider resolution against the shared tapto config store.
//
// Lifted verbatim from tapto-code's main.cpp (the anonymous namespace around
// lines 410-618), because tapto-word needs the same resolution and a second
// copy would drift. This header is the intended home for it in both programs:
// when tapto-code is next touched, delete its private copy and include this.
//
// A provider has a *name* and a *dialect*, and they are not the same thing.
// The name selects a block of config keys and is free-form — qwen36, gemma4,
// work-claude. The dialect is one of the three request shapes we can speak,
// named by that block's `<name>-provider-type` key:
//
//   qwen36-provider-type = openai         gemma4-provider-type = openai
//   qwen36-provider-url  = http://a:8000  gemma4-provider-url  = http://b:8081
//   qwen36-model         = Qwen3-VL-30B   gemma4-model         = gemma-3-27b
//   qwen36-api-key       = local          gemma4-api-key       = local
//
// The store is shared with tapto-code and tapto-vnc, which read the same
// blocks. tapto-word adds no keys of its own beyond the `word-` block below.
// ---------------------------------------------------------------------------

namespace tapto {

struct EffectiveEntry {
    std::string key;
    std::string value;
    Level origin;
};

// Merge all scopes lowest-to-highest so later scopes override earlier ones,
// while preserving first-seen ordering of keys.
std::vector<EffectiveEntry> effective_config();

// Look up a config key's effective value across all scopes. A key present but
// empty counts as unset, so `model =` falls back to the default instead of
// asking the provider for a model with no name.
std::optional<std::string> get_effective(const std::string& key);

// The request shapes this program can speak. Used as a provider name, each one
// means its own dialect with that vendor's defaults, so `claude`, `openai` and
// `gemini` need no block at all.
bool is_dialect(const std::string& s);

// A provider block resolved into everything a chat session needs.
struct ResolvedProvider {
    std::string name;    // the config block, e.g. "qwen36"
    std::string dialect; // claude | openai | gemini
    std::string url;
    std::string model;
    std::string reasoning_effort; // empty when unset; openai dialect only
    Secret api_key;      // unresolved if none is configured; the caller decides
};

// Resolve a provider name (empty for the configured default). Prints its own
// error and returns nullopt when the name names no dialect this program speaks.
std::optional<ResolvedProvider> resolve_provider(const std::string& requested);

// How the provider is shown to the user: the block name, plus the dialect when
// it adds something the name doesn't already say.
std::string provider_label(const ResolvedProvider& p);

} // namespace tapto

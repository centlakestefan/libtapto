// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Centlake Software AB

// The image plugin: lets a model that can see look at image files.
//
// An image file is binary, so the core's text tools refuse it, and a model
// that can see needs another way in. Not every server can see, though, and a
// tool offered to one that cannot is noise, so this is a plugin: loaded with
// /add-plugin image, or `plugin.image = ro`, where it is wanted.
//
// image_read decodes the file, re-encodes it as PNG (every provider takes
// PNG; it also normalises JPEG/BMP/GIF into one shape) and hands the
// bytes to the host with ITaptoHost::AttachImage, which attaches them to the
// model's turn in the provider's shape. The path is the host's business: it is
// marked "x-tapto-path": "read", so the host resolves and checks it before the
// call and this plugin only ever sees an absolute path the model may read.
//
// What the plugin controls is size: a model's pixel budget is a fraction of a
// megapixel, so the longest side is capped at kMaxImageSide (down-scaled with
// a box filter rather than nearest-neighbour, which would leave jaggies on a
// 4K screenshot), and a file whose header claims dimensions past kMaxImageDim
// is refused before it is decoded, since decoding it would allocate
// gigabytes first.
//
// stb_image is a single-header decoder and stb_image_write a single-header
// PNG encoder; their implementations are compiled into this file. Every
// decoder parses untrusted bytes, and stb picks one by sniffing the content,
// not the file's extension, so only the formats image_read names are compiled
// in (STBI_ONLY_*): PNG, JPEG, BMP and GIF (its first frame). The rest (TGA,
// PSD, HDR, PIC, PNM) are left out, not merely unlisted; TGA especially,
// which has no magic number, so stb would try it on whatever the others
// reject.

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "tapto/plugin.h"

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4996) // stb_image_write.h uses sprintf internally
#pragma warning(disable : 4244 4245 4100 4456 4457 4702) // stb's own conversions
#elif defined(__GNUC__)
// stb's own code, as GCC and Clang see it: struct initializers that leave
// members out, unused parameters and the like. Not ours to change.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wsign-compare"
#endif
#define STB_IMAGE_IMPLEMENTATION
#define STBI_ONLY_PNG
#define STBI_ONLY_JPEG
#define STBI_ONLY_BMP
#define STBI_ONLY_GIF
#include "stb_image.h"
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"
#ifdef _MSC_VER
#pragma warning(pop)
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

namespace fs = std::filesystem;
using json = nlohmann::json;
using scom::SRESULT;
using tapto::TaptoString;

namespace {

constexpr int kMaxImageSide = 1600;
constexpr int kMaxImageDim = 16384;

SRESULT hand_out(std::string_view s, char*& out) {
    TaptoString t = TaptoString::copy(s);
    if (!t) return scom::ERR_NO_MEMORY;
    out = t.detach();
    return scom::OK;
}

std::string lower_ext(const fs::path& p) {
    std::string e = p.extension().u8string();
    if (!e.empty() && e[0] == '.') e.erase(0, 1);
    for (char& c : e) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return e;
}

bool has_image_ext(const fs::path& p) {
    const std::string e = lower_ext(p);
    return e == "png" || e == "jpg" || e == "jpeg" || e == "bmp" || e == "gif";
}

// Text, as far as a glance at the start tells: no NUL in the first 8 KB.
bool looks_binary(const std::string& s) {
    return s.find('\0', 0) < std::min<std::size_t>(s.size(), 8192);
}

// Average a rectangular block of `src` into one pixel. Box down-scale: each
// destination pixel is the mean of the source pixels it maps over. `src` is
// w*h*comp bytes, `dst` (filled) is out_w*out_h*comp. A box is always at
// least one source pixel, so a no-op size still copies.
void box_downscale(const uint8_t* src, int w, int h, int comp, int out_w, int out_h,
                   std::vector<uint8_t>& dst) {
    dst.assign(static_cast<std::size_t>(out_w) * out_h * comp, 0);
    uint64_t acc[4] = {0, 0, 0, 0};
    for (int oy = 0; oy < out_h; ++oy) {
        const int y0 = oy * h / out_h;
        int y1 = (oy + 1) * h / out_h;
        if (y1 <= y0) y1 = y0 + 1;
        for (int ox = 0; ox < out_w; ++ox) {
            const int x0 = ox * w / out_w;
            int x1 = (ox + 1) * w / out_w;
            if (x1 <= x0) x1 = x0 + 1;
            for (int c = 0; c < comp; ++c) acc[c] = 0;
            uint64_t npix = 0;
            for (int y = y0; y < y1; ++y) {
                const uint8_t* row = src + (static_cast<std::size_t>(y) * w + x0) * comp;
                for (int x = x0; x < x1; ++x) {
                    for (int c = 0; c < comp; ++c)
                        acc[c] += row[static_cast<std::size_t>(x - x0) * comp + c];
                    ++npix;
                }
            }
            uint8_t* d = dst.data() + (static_cast<std::size_t>(oy) * out_w + ox) * comp;
            for (int c = 0; c < comp; ++c)
                d[c] = static_cast<uint8_t>((acc[c] + npix / 2) / npix);
        }
    }
}

// stb_image_write has no write-to-memory API, only a callback, which appends
// the PNG bytes to a vector as the encoder emits them.
void png_write_cb(void* context, void* data, int size) {
    auto* out = static_cast<std::vector<uint8_t>*>(context);
    out->insert(out->end(), static_cast<const uint8_t*>(data),
                static_cast<const uint8_t*>(data) + size);
}

// Encode a decoded image (w x h, `comp` channels) as PNG into `out`, first
// box-rescaled so its longest side is kMaxImageSide when `downscale`. False
// on failure; `out_w`/`out_h` are the encoded size.
bool png_encode(const uint8_t* px, int w, int h, int comp, bool downscale,
                std::vector<uint8_t>& out, int& out_w, int& out_h) {
    out_w = w;
    out_h = h;
    std::vector<uint8_t> scaled;
    const uint8_t* data = px;
    if (downscale) {
        const double scale = static_cast<double>(kMaxImageSide) / std::max(w, h);
        out_w = std::max(1, static_cast<int>(w * scale + 0.5));
        out_h = std::max(1, static_cast<int>(h * scale + 0.5));
        box_downscale(px, w, h, comp, out_w, out_h, scaled);
        data = scaled.data();
    }
    out.clear();
    out.reserve(static_cast<std::size_t>(out_w) * out_h * comp * 3 / 2 + 4096);
    if (!stbi_write_png_to_func(png_write_cb, &out, out_w, out_h, comp, data, out_w * comp)) {
        out.clear();
        return false;
    }
    return !out.empty();
}

std::string read_image(const std::string& path_utf8) {
    if (path_utf8.empty()) return "ERROR: 'path' not present.";
    const fs::path path = fs::u8path(path_utf8);
    // The model knows the file by the name it gave; the absolute path the
    // host resolved it to stays out of the conversation.
    const std::string name = path.filename().u8string();
    std::error_code ec;
    if (!fs::exists(path, ec)) return "ERROR: Not found: " + name;
    if (fs::is_directory(path, ec)) return "ERROR: '" + name + "' is a directory, not an image file.";

    std::string raw;
    {
        std::ifstream in(path, std::ios::binary);
        if (!in) return "ERROR: Failed to read " + name;
        raw.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }
    const auto* bytes = reinterpret_cast<const stbi_uc*>(raw.data());
    const int len = static_cast<int>(std::min<std::size_t>(raw.size(), INT32_MAX));

    int w = 0, h = 0, comp = 0;
    if (!stbi_info_from_memory(bytes, len, &w, &h, &comp)) {
        const std::string what =
            has_image_ext(path) ? "an image, but it could not be decoded (a corrupted or unusual variant?)"
            : looks_binary(raw) ? "binary, so it is not an image"
                                : "not an image";
        return "ERROR: " + name + " is " + what +
               ". Use the editor's 'view' (or the built-in cat/head) to read its text.";
    }
    // Refused on the dimensions its header claims, before decoding them
    // would allocate gigabytes.
    if (w > kMaxImageDim || h > kMaxImageDim) {
        return "ERROR: " + name + " is " + std::to_string(w) + "x" + std::to_string(h) +
               ", which image_read does not decode (its longest side must be at most " +
               std::to_string(kMaxImageDim) + " pixels). Downscale it first and try again.";
    }

    stbi_uc* px = stbi_load_from_memory(bytes, len, &w, &h, &comp, 0);
    if (!px) return "ERROR: " + name + " is an image, but it could not be decoded.";
    // The encoder writes the native channel count; box_downscale averages
    // per channel, so no conversion is needed either side of it.
    const bool downscale = std::max(w, h) > kMaxImageSide;
    std::vector<uint8_t> png;
    int out_w = w, out_h = h;
    const bool encoded = png_encode(px, w, h, comp, downscale, png, out_w, out_h);
    stbi_image_free(px);
    if (!encoded) return "ERROR: " + name + " decoded but could not be re-encoded as PNG.";

    // The label is the host's: a null one names the image by the path the
    // model wrote.
    if (tapto::plugin_host()->AttachImage(png.data(), png.size(), nullptr) != scom::OK)
        return "ERROR: the image of " + name + " could not be attached.";

    std::ostringstream r;
    r << "image attached: " << out_w << "x" << out_h << " PNG";
    if (downscale) r << " (down-scaled from " << w << "x" << h << ")";
    return r.str();
}

void release_host() {
    if (tapto::ITaptoHost*& h = tapto::plugin_host()) {
        h->Release();
        h = nullptr;
    }
}

class ImagePlugin final : public scom::Base,
                    public tapto::ITaptoPlugin,
                    public tapto::ITaptoPluginUnload {
public:
    SCOM_IMPLEMENT_BASE_EX(ImagePlugin, tapto::ITaptoPlugin)
    SCOM_BEGIN_INTERFACE_MAP(ImagePlugin)
        SCOM_INTERFACE(tapto::ITaptoPlugin)
        SCOM_INTERFACE(tapto::ITaptoPluginUnload)
    SCOM_END_INTERFACE_MAP()

    SRESULT SCOM_CALL Describe(char*& json_out) override {
        const json d = {
            {"name", "image"},
            {"version", "1.0.0"},
            {"prompt",
             "To look at an image file (PNG, JPEG, BMP, GIF), use image_read: "
             "the text tools refuse binary files."},
            {"tools", json::array({{
                {"name", "image_read"},
                {"description",
                 "Read an image file (PNG, JPEG, BMP, GIF) and attach it to "
                 "your reply for you to see. The image is normalised to PNG, and its "
                 "longest side is capped at 1600 pixels (down-scaled when larger); images "
                 "over 16384 pixels on a side are refused. Use it when a file you want to "
                 "look at is an image: the text tools (view, cat, head) refuse binary "
                 "files. The path resolves the same as the editor's: relative to the "
                 "working directory, or under a granted folder / @tmp / @memory."},
                {"schema",
                 {{"type", "object"},
                  {"properties",
                   {{"path",
                     {{"type", "string"},
                      {"description", "Image file to read."},
                      {"x-tapto-path", "read"}}}}},
                  {"required", {"path"}}}},
                {"writes", false},
            }})},
        };
        return hand_out(d.dump(), json_out);
    }

    SRESULT SCOM_CALL Configure(const char*) override { return scom::OK; }

    SRESULT SCOM_CALL CallTool(const char* name, const char* json_args,
                               char*& result_out) override {
        std::string result;
        try {
            const std::string tool = name ? name : "";
            if (tool != "image_read") {
                result = "ERROR: the image plugin has no tool " + tool;
            } else {
                const json args = json::parse(json_args ? json_args : "{}", nullptr, false);
                const std::string path = args.is_object() && args.contains("path") &&
                                                 args["path"].is_string()
                                             ? args["path"].get<std::string>()
                                             : std::string();
                result = read_image(path);
            }
        } catch (const std::exception& e) {
            // Nothing may leave a call as an exception.
            result = std::string("ERROR: image_read failed: ") + e.what();
        }
        return hand_out(result, result_out);
    }

    SRESULT SCOM_CALL Shutdown() override {
        release_host();
        return scom::OK;
    }

private:
    ~ImagePlugin() { release_host(); }

    tapto::PluginObjectCount m_count;
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
    auto* p = new ImagePlugin;
    const SRESULT r = p->QueryInterface(riid, ppv);
    p->Release();
    return r;
}

TAPTO_PLUGIN_EXPORT SRESULT SCOM_CALL TaptoCanUnloadNow() {
    return tapto::plugin_objects() == 0 ? scom::OK : scom::ST_FALSE;
}

# libtapto

The code the tapto programs share: the config store and secret resolver,
provider resolution, the three provider clients with the agent loop inside, and
the helpers they lean on — UTF-8 sanitising, file and search tools, tool
images, certificates, logging.

It is one static library, built by [tapto-code](https://github.com/centlakestefan/tapto-code)
(an AI coding CLI), [tapto-vnc](https://github.com/centlakestefan/tapto-vnc)
and their siblings. Nothing here knows which program it is in.

Apache-2.0. C++17. Windows, Linux and macOS.

## Using it

```cmake
include(FetchContent)
FetchContent_Declare(libtapto
  GIT_REPOSITORY https://github.com/centlakestefan/libtapto.git
  GIT_TAG        v0.1.0          # pin a tag; never a branch
)
FetchContent_MakeAvailable(libtapto)

target_link_libraries(your-program PRIVATE tapto::tapto)
```

That is the whole integration. The target carries its own include directory,
its compile definitions and its dependencies, so a consumer repeats none of
them.

### What you must provide: `tapto::ui`

`tapto/ui.h` is **declared** by this library and **defined** by the program.
The library calls `set_status()` and friends; what they do — a terminal row, an
SSE frame, nothing at all — is the program's business. A program that links
this library and defines none of them will not link.

`test/ui_null.cpp` is a do-nothing implementation. Link it in tests, or in any
program with no UI of its own.

### Dependencies

Fetched and pinned here, so every program moves together when they are bumped:

| Dependency | How it arrives |
| ---------- | -------------- |
| [nlohmann/json](https://github.com/nlohmann/json) 3.11.3 | FetchContent |
| [cpp-httplib](https://github.com/yhirose/cpp-httplib) 0.15.3 | FetchContent |
| OpenSSL | found on the system; on Windows with none, a pinned prebuilt is fetched |
| Threads | `find_package` |

A consumer that has already defined `nlohmann_json::nlohmann_json` or
`httplib::httplib` keeps its own — the declarations here are skipped — so a
program may bring its own pins instead.

`-DLIBTAPTO_STATIC_SSL=ON` links OpenSSL and zlib statically where a static
build of them exists.

## Building it on its own

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

The tests are plain executables with assertions of their own, so ctest needs no
framework fetched or installed. They build by default only when this is the
top-level project; a consumer that wants them sets `LIBTAPTO_BUILD_TESTS=ON`.

## What belongs here

What is program-independent. A program's own entry point, its tools, its
commands and its UI implementation stay in the program. The boundary is worth
defending: it is what lets one fix reach every program at once.

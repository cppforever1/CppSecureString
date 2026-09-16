# CppSecureString

CppSecureString is a small C++20 library for Windows and Linux that keeps string contents encrypted while they are idle in RAM. It provides `SecureString` for `char` and `WSecureString` for `wchar_t`, with a familiar subset of `std::string` operations.

The library has no third-party dependencies. It uses an internal ChaCha20 implementation, `BCryptGenRandom` on Windows, and `getrandom` on Linux. Key pages are locked with `VirtualLock` or `mlock` when the operating system permits it, and Linux key pages are also marked `MADV_DONTDUMP`.

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

The demo executable is `CppSecureStringDemo`. Disable optional targets with `CPPSECURESTRING_BUILD_DEMO=OFF` or `CPPSECURESTRING_BUILD_TESTS=OFF`.

## Use

```cpp

#include "cppsecurestring/secure_string.hpp"

#include <iostream>
#include <string>
#include <string_view>

int main() {
    cppsecurestring::SecureString password;

    std::cout << "Enter a secret: ";

    // Read password using stream extraction without exposing plaintext in memory
    std::cin >> password;
    
    std::cout << "Stored " << password.size() << " encrypted characters in memory.\n";
    
    // Display the entered password (still encrypted in memory)
    std::cout << "password entered. " << password << std::endl;

    // Access the plaintext within a controlled scope
    password.with_plaintext([](std::string_view plaintext) {
        std::cout << "Plaintext is available only inside this callback: " << plaintext << '\n';
    });

    // Explicitly reveal the password (use with caution)
    std::string revealed = password.reveal();
    std::cout << "Explicitly revealed copy: " << revealed << '\n';
    cppsecurestring::detail::secure_wipe(revealed.data(), revealed.size());
}

Link the CMake target:

```cmake
add_subdirectory(path/to/CppSecureString)
target_link_libraries(your_target PRIVATE CppSecureString::CppSecureString)
```

Installed packages can use `find_package(CppSecureString CONFIG REQUIRED)` with the same target name.

## How it works

The library stores the secret as ciphertext in a `std::vector<std::byte>` and keeps a per-instance key and nonce in memory. Every mutation re-encrypts the content with a fresh nonce, so a previous version of the string is not left behind in the same buffer.

Each `SecureString token("temporary")` instance generates a fresh random 256-bit encryption key and a fresh random 96-bit nonce. Therefore, identical plaintext values produce different ciphertext in separate instances and after mutations.

On Linux, the key buffer is optionally locked with `mlock` and the page is marked `MADV_DONTDUMP` so crash dumps and some memory scanners are less likely to reveal it. On Windows, the equivalent path uses `VirtualLock` and the Windows RNG API.

The class is not a drop-in replacement for `std::string` in the sense of exposing a raw buffer. It intentionally avoids `data()` and `c_str()`, because exposing a live plaintext pointer would defeat the purpose of encrypted-at-rest storage. Instead, read or modify the value only inside a controlled step.

## Typical usage patterns

### Read a secret from input and wipe the original buffer

```cpp
std::string input;
std::getline(std::cin, input);

cppsecurestring::SecureString password(input);
cppsecurestring::detail::secure_wipe(input.data(), input.size());
input.clear();
```

This pattern is important when the input came from a console, file, or network buffer that should not remain in plaintext RAM longer than necessary.

### Do work in plaintext only for a short time

```cpp
bool valid = password.with_plaintext([](std::string_view value) {
    return value.size() >= 12 && value.find("!") != std::string_view::npos;
});
```

The callback receives a view of the decrypted content, and that temporary buffer is wiped immediately when the callback returns.

### Create an explicit plaintext copy only when you must

```cpp
std::string copy = password.reveal();
cppsecurestring::detail::secure_wipe(copy.data(), copy.size());
```

This is intentionally explicit, because plaintext copies are exactly the kind of value that can leak via logs, crash dumps, or debugger inspection.

## Why use this instead of std::string?

`std::string` is great for ordinary application data, but it leaves the plaintext characters in memory as a normal buffer. CppSecureString changes that trade-off:

- the in-memory payload is encrypted while idle
- temporary plaintext exists only while the value is actively being read or modified
- secret data is not accidentally exposed through a raw pointer, `c_str()`, or debugger-friendly string buffer

This does not make secrets immune to a malicious or privileged process. If an attacker can pause your program or read the process memory while the plaintext is materialized, they can still observe the value. The library is best used as a defense-in-depth measure, not as a security boundary by itself.

## API

Both string types support construction, copy/move, assignment, indexed access, bounds-checked `at`, iterators, `append`, `insert`, `erase`, `replace`, `resize`, `substr`, `find`, comparison, `starts_with`, `ends_with`, and capacity operations.

There is deliberately no `data()` or `c_str()`: returning a stable plaintext pointer would defeat encrypted-at-rest storage. Const element access returns a character by value, and mutable access uses a proxy. Prefer `with_plaintext()` for efficient bulk work; `reveal()` intentionally creates a normal plaintext string that the caller must wipe.

The library also supports stream-style I/O for convenience:

```cpp
cppsecurestring::SecureString password;
std::cin >> password;
std::cout << password;
```

This is useful for interactive console input while still keeping the stored password encrypted in memory.

## Security model

CppSecureString reduces accidental disclosure from ordinary memory scans, crash dumps, debugger string searches, allocator leftovers, and unintended long-lived plaintext copies. Ciphertext is re-encrypted with a fresh 96-bit nonce after each mutation. Temporary buffers and released allocations are explicitly wiped.

It is defense in depth, not a boundary against an attacker controlling the process:

- A privileged or attached debugger can locate the key and decrypt memory, or pause execution while plaintext is in use.
- Plaintext necessarily exists briefly during construction and operations. Inputs, returned values, logs, streams, compiler string literals, and callback-created copies are outside the library's control.
- `VirtualLock` and `mlock` can fail because of permissions or resource limits. Check `key_is_locked()` when locked key pages are a requirement.
- ChaCha20 provides confidentiality here, not tamper detection. This class does not replace authenticated encryption for stored or transmitted data.
- Optimizers, operating systems, crash handlers, and hardware can make absolute erasure guarantees impossible in portable C++.

Avoid embedding real secrets in source literals. Read them into a temporary buffer, construct the secure string, wipe the input immediately, and minimize work performed inside `with_plaintext()`.

## Platform requirements

- C++20 compiler
- CMake 3.20 or newer
- Windows 10+ with BCrypt, or Linux with `getrandom`, `mlock`, and `madvise`

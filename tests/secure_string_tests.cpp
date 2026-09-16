#include "cppsecurestring/secure_string.hpp"

#include <array>
#include <cstddef>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

using cppsecurestring::SecureString;
using cppsecurestring::WSecureString;

namespace {

int failures = 0;

void expect(bool condition, std::string_view message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

void test_construction_and_access() {
    SecureString secret("hunter2");
    expect(secret.size() == 7, "size after construction");
    expect(secret.front() == 'h' && secret.back() == '2', "front and back");
    expect(secret.reveal() == "hunter2", "explicit reveal");
    secret[0] = 'H';
    expect(secret == "Hunter2", "mutable character proxy");
}

void test_string_operations() {
    SecureString value("alpha");
    value += " beta";
    value.push_back('!');
    expect(value == "alpha beta!", "append and push_back");
    value.replace(6, 4, "gamma");
    expect(value.find("gamma") == 6, "replace and find");
    expect(value.substr(6, 5) == "gamma", "substr");
    value.erase(5);
    expect(value == "alpha", "erase");
}

void test_copy_move_and_callback() {
    SecureString original("private");
    SecureString copy(original);
    SecureString moved(std::move(copy));
    expect(original == moved, "copy and move preserve value");
    SecureString assigned("old");
    assigned = std::move(moved);
    expect(assigned == "private", "move assignment preserves value");
    const auto length = moved.with_plaintext([](std::string_view value) { return value.size(); });
    expect(length == 0, "moved-from object remains valid");
    const auto assigned_length = assigned.with_plaintext([](std::string_view value) { return value.size(); });
    expect(assigned_length == 7, "scoped plaintext callback");
}

void test_wide_string() {
    WSecureString value(L"wide secret");
    value += L"!";
    expect(value.reveal() == L"wide secret!", "wide string support");
}

void test_stream_io() {
    std::stringstream input;
    input << "secret";
    cppsecurestring::SecureString value;
    input >> value;
    expect(value == "secret", "stream extraction");

    std::stringstream output;
    output << value;
    expect(output.str() == "secret", "stream insertion");
}

void test_remaining_api() {
    SecureString value("abc");
    expect(value.empty() == false, "empty false for non-empty");
    value.insert(1, "X");
    expect(value == "aXbc", "insert");
    value.pop_back();
    expect(value == "aXb", "pop_back");
    value.clear();
    expect(value.empty(), "clear empties the string");

    SecureString text("Hello World");
    expect(text.compare("Hello World") == 0, "compare equality");
    expect(text.compare("Hello") > 0, "compare greater than");
    expect(text.starts_with("Hello"), "starts_with");
    expect(text.ends_with("World"), "ends_with");
    expect(text.find("World") == 6, "find");

    text.reserve(64);
    text.shrink_to_fit();
    expect(text == "Hello World", "reserve and shrink_to_fit preserve content");

    SecureString left("left");
    SecureString right("right");
        const auto left_locked = left.key_is_locked();
        const auto right_locked = right.key_is_locked();
    swap(left, right);
    expect(left == "right" && right == "left", "swap");
            expect(left.key_is_locked() == left_locked && right.key_is_locked() == right_locked,
                "swap preserves key storage lock state");

    auto begin = text.begin();
    auto end = text.end();
    expect(begin != end, "iterator begin not end");
    expect(*begin == 'H', "iterator dereference");
    ++begin;
    expect(*begin == 'e', "iterator increment");
    expect(std::distance(text.begin(), text.end()) == static_cast<std::ptrdiff_t>(text.size()), "iterator distance");
}

void test_bounds() {
    SecureString value("x");
    try {
        (void)value.at(2);
        expect(false, "at throws out_of_range");
    } catch (const std::out_of_range&) {
        expect(true, "at throws out_of_range");
    }
}

void test_chacha20_vector() {
    std::array<std::byte, 32> key{};
    for (std::size_t index = 0; index < key.size(); ++index) key[index] = std::byte(index);
    const std::array<std::byte, 12> nonce{
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x09},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x4a},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}
    };
    const std::array<std::byte, 64> expected{
        std::byte{0x10}, std::byte{0xf1}, std::byte{0xe7}, std::byte{0xe4}, std::byte{0xd1}, std::byte{0x3b}, std::byte{0x59}, std::byte{0x15},
        std::byte{0x50}, std::byte{0x0f}, std::byte{0xdd}, std::byte{0x1f}, std::byte{0xa3}, std::byte{0x20}, std::byte{0x71}, std::byte{0xc4},
        std::byte{0xc7}, std::byte{0xd1}, std::byte{0xf4}, std::byte{0xc7}, std::byte{0x33}, std::byte{0xc0}, std::byte{0x68}, std::byte{0x03},
        std::byte{0x04}, std::byte{0x22}, std::byte{0xaa}, std::byte{0x9a}, std::byte{0xc3}, std::byte{0xd4}, std::byte{0x6c}, std::byte{0x4e},
        std::byte{0xd2}, std::byte{0x82}, std::byte{0x64}, std::byte{0x46}, std::byte{0x07}, std::byte{0x9f}, std::byte{0xaa}, std::byte{0x09},
        std::byte{0x14}, std::byte{0xc2}, std::byte{0xd7}, std::byte{0x05}, std::byte{0xd9}, std::byte{0x8b}, std::byte{0x02}, std::byte{0xa2},
        std::byte{0xb5}, std::byte{0x12}, std::byte{0x9c}, std::byte{0xd1}, std::byte{0xde}, std::byte{0x16}, std::byte{0x4e}, std::byte{0xb9},
        std::byte{0xcb}, std::byte{0xd0}, std::byte{0x83}, std::byte{0xe8}, std::byte{0xa2}, std::byte{0x50}, std::byte{0x3c}, std::byte{0x4e}
    };
    std::array<std::byte, 64> zeros{};
    std::array<std::byte, 64> output{};
    cppsecurestring::detail::chacha20_xor(zeros, output, key, nonce, 64);
    expect(output == expected, "RFC 8439 ChaCha20 block test vector");
}

} // namespace

int main() {
    test_construction_and_access();
    test_string_operations();
    test_copy_move_and_callback();
    test_wide_string();
    test_stream_io();
    test_remaining_api();
    test_bounds();
    test_chacha20_vector();
    if (failures == 0) std::cout << "All CppSecureString tests passed\n";
    return failures == 0 ? 0 : 1;
}

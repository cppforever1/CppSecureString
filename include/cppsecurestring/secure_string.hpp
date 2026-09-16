#pragma once

#include <algorithm>
#include <array>
#include <compare>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iterator>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace cppsecurestring {
namespace detail {

void secure_wipe(void* data, std::size_t size) noexcept;
void secure_random(std::span<std::byte> output);
bool lock_memory(void* data, std::size_t size) noexcept;
void unlock_memory(void* data, std::size_t size) noexcept;
void chacha20_xor(std::span<const std::byte> input,
                  std::span<std::byte> output,
                  std::span<const std::byte, 32> key,
                  std::span<const std::byte, 12> nonce,
                  std::size_t stream_offset = 0) noexcept;

template <typename T>
class secure_allocator {
public:
    using value_type = T;

    secure_allocator() noexcept = default;
    template <typename U>
    secure_allocator(const secure_allocator<U>&) noexcept {}

    [[nodiscard]] T* allocate(std::size_t count) {
        return std::allocator<T>{}.allocate(count);
    }
    void deallocate(T* pointer, std::size_t count) noexcept {
        secure_wipe(pointer, count * sizeof(T));
        std::allocator<T>{}.deallocate(pointer, count);
    }
};

template <typename T, typename U>
bool operator==(const secure_allocator<T>&, const secure_allocator<U>&) noexcept { return true; }

template <typename CharT>
class plaintext_buffer final {
public:
    explicit plaintext_buffer(std::size_t count) : data_(count) {}
    ~plaintext_buffer() { secure_wipe(data_.data(), data_.size() * sizeof(CharT)); }

    plaintext_buffer(const plaintext_buffer&) = delete;
    plaintext_buffer& operator=(const plaintext_buffer&) = delete;

    std::span<CharT> span() noexcept { return data_; }
    std::basic_string_view<CharT> view() const noexcept { return {data_.data(), data_.size()}; }

private:
    std::vector<CharT> data_;
};

} // namespace detail

template <typename CharT, typename Traits = std::char_traits<CharT>>
class basic_secure_string final {
    static_assert(std::is_trivial_v<CharT> && std::is_standard_layout_v<CharT>);

public:
    using traits_type = Traits;
    using value_type = CharT;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using string_type = std::basic_string<CharT, Traits>;
    using string_view_type = std::basic_string_view<CharT, Traits>;
    static constexpr size_type npos = string_view_type::npos;

    class reference {
    public:
        reference& operator=(CharT value) {
            owner_->set(index_, value);
            return *this;
        }
        reference& operator=(const reference& other) { return *this = static_cast<CharT>(other); }
        operator CharT() const { return owner_->value_at(index_); }

    private:
        friend class basic_secure_string;
        reference(basic_secure_string& owner, size_type index) : owner_(&owner), index_(index) {}
        basic_secure_string* owner_;
        size_type index_;
    };

    template <bool IsConst>
    class iterator_base {
    public:
        using iterator_category = std::random_access_iterator_tag;
        using iterator_concept = std::random_access_iterator_tag;
        using value_type = CharT;
        using difference_type = std::ptrdiff_t;
        using reference = std::conditional_t<IsConst, CharT, typename basic_secure_string::reference>;

        iterator_base() = default;
        reference operator*() const { return (*owner_)[index_]; }
        reference operator[](difference_type offset) const { return *(*this + offset); }
        iterator_base& operator++() { ++index_; return *this; }
        iterator_base operator++(int) { auto copy = *this; ++*this; return copy; }
        iterator_base& operator--() { --index_; return *this; }
        iterator_base operator--(int) { auto copy = *this; --*this; return copy; }
        iterator_base& operator+=(difference_type offset) { index_ += offset; return *this; }
        iterator_base& operator-=(difference_type offset) { return *this += -offset; }

        friend iterator_base operator+(iterator_base iterator, difference_type offset) { return iterator += offset; }
        friend iterator_base operator+(difference_type offset, iterator_base iterator) { return iterator += offset; }
        friend iterator_base operator-(iterator_base iterator, difference_type offset) { return iterator -= offset; }
        friend difference_type operator-(const iterator_base& left, const iterator_base& right) {
            return static_cast<difference_type>(left.index_) - static_cast<difference_type>(right.index_);
        }
        friend auto operator<=>(const iterator_base&, const iterator_base&) = default;

    private:
        friend class basic_secure_string;
        using owner_type = std::conditional_t<IsConst, const basic_secure_string, basic_secure_string>;
        iterator_base(owner_type& owner, size_type index) : owner_(&owner), index_(index) {}
        owner_type* owner_ = nullptr;
        size_type index_ = 0;
    };

    using iterator = iterator_base<false>;
    using const_iterator = iterator_base<true>;

    basic_secure_string() { initialize_key(); }
    basic_secure_string(string_view_type value) : basic_secure_string() { assign(value); }
    basic_secure_string(const CharT* value) : basic_secure_string(string_view_type(value)) {}
    basic_secure_string(size_type count, CharT value) : basic_secure_string() {
        detail::plaintext_buffer<CharT> plain(count);
        std::fill(plain.span().begin(), plain.span().end(), value);
        assign(plain.view());
    }

    basic_secure_string(const basic_secure_string& other) : basic_secure_string() {
        other.with_plaintext([this](string_view_type value) { assign(value); });
    }

    basic_secure_string(basic_secure_string&& other) noexcept
        : encrypted_(std::move(other.encrypted_)), size_(std::exchange(other.size_, 0)),
                    key_(other.key_), nonce_(other.nonce_), key_locked_(detail::lock_memory(key_.data(), key_.size())) {
                detail::secure_wipe(other.key_.data(), other.key_.size());
                if (other.key_locked_) detail::unlock_memory(other.key_.data(), other.key_.size());
        other.key_locked_ = false;
        detail::secure_wipe(other.nonce_.data(), other.nonce_.size());
        other.initialize_key_noexcept();
    }

    ~basic_secure_string() {
        wipe_ciphertext();
        detail::secure_wipe(key_.data(), key_.size());
        if (key_locked_) detail::unlock_memory(key_.data(), key_.size());
    }

    basic_secure_string& operator=(const basic_secure_string& other) {
        if (this != &other) other.with_plaintext([this](string_view_type value) { assign(value); });
        return *this;
    }

    basic_secure_string& operator=(basic_secure_string&& other) noexcept {
        if (this == &other) return *this;
        wipe_ciphertext();
        detail::secure_wipe(key_.data(), key_.size());
        if (key_locked_) detail::unlock_memory(key_.data(), key_.size());
        encrypted_ = std::move(other.encrypted_);
        size_ = std::exchange(other.size_, 0);
        key_ = other.key_;
        nonce_ = other.nonce_;
        key_locked_ = detail::lock_memory(key_.data(), key_.size());
        detail::secure_wipe(other.key_.data(), other.key_.size());
        if (other.key_locked_) detail::unlock_memory(other.key_.data(), other.key_.size());
        other.key_locked_ = false;
        detail::secure_wipe(other.nonce_.data(), other.nonce_.size());
        other.initialize_key_noexcept();
        return *this;
    }

    basic_secure_string& operator=(string_view_type value) { assign(value); return *this; }
    basic_secure_string& operator=(const CharT* value) { return *this = string_view_type(value); }

    [[nodiscard]] bool empty() const noexcept { return size_ == 0; }
    [[nodiscard]] size_type size() const noexcept { return size_; }
    [[nodiscard]] size_type length() const noexcept { return size_; }
    [[nodiscard]] size_type max_size() const noexcept { return encrypted_.max_size() / sizeof(CharT); }
    [[nodiscard]] size_type capacity() const noexcept { return encrypted_.capacity() / sizeof(CharT); }
    [[nodiscard]] bool key_is_locked() const noexcept { return key_locked_; }

    void reserve(size_type capacity) { encrypted_.reserve(checked_bytes(capacity)); }
    void shrink_to_fit() { encrypted_.shrink_to_fit(); }
    void clear() noexcept { wipe_ciphertext(); size_ = 0; }

    CharT operator[](size_type index) const { return value_at(index); }
    reference operator[](size_type index) { return reference(*this, index); }
    CharT at(size_type index) const {
        if (index >= size_) throw std::out_of_range("basic_secure_string::at");
        return value_at(index);
    }
    reference at(size_type index) {
        if (index >= size_) throw std::out_of_range("basic_secure_string::at");
        return reference(*this, index);
    }
    CharT front() const { return at(0); }
    reference front() { return at(0); }
    CharT back() const { return at(size_ - 1); }
    reference back() { return at(size_ - 1); }

    iterator begin() noexcept { return iterator(*this, 0); }
    iterator end() noexcept { return iterator(*this, size_); }
    const_iterator begin() const noexcept { return const_iterator(*this, 0); }
    const_iterator end() const noexcept { return const_iterator(*this, size_); }
    const_iterator cbegin() const noexcept { return begin(); }
    const_iterator cend() const noexcept { return end(); }

    basic_secure_string& assign(string_view_type value) {
        encrypt(std::as_bytes(std::span(value.data(), value.size())));
        size_ = value.size();
        return *this;
    }

    basic_secure_string& append(string_view_type value) {
        mutate([value](string_type& plain) { plain.append(value); });
        return *this;
    }
    basic_secure_string& operator+=(string_view_type value) { return append(value); }
    basic_secure_string& operator+=(CharT value) { push_back(value); return *this; }
    void push_back(CharT value) { mutate([value](string_type& plain) { plain.push_back(value); }); }
    void pop_back() { mutate([](string_type& plain) { plain.pop_back(); }); }

    basic_secure_string& insert(size_type index, string_view_type value) {
        mutate([=](string_type& plain) { plain.insert(index, value); });
        return *this;
    }
    basic_secure_string& erase(size_type index = 0, size_type count = npos) {
        mutate([=](string_type& plain) { plain.erase(index, count); });
        return *this;
    }
    basic_secure_string& replace(size_type index, size_type count, string_view_type value) {
        mutate([=](string_type& plain) { plain.replace(index, count, value); });
        return *this;
    }
    void resize(size_type count, CharT value = CharT()) {
        mutate([=](string_type& plain) { plain.resize(count, value); });
    }

    [[nodiscard]] basic_secure_string substr(size_type index = 0, size_type count = npos) const {
        return with_plaintext([=](string_view_type plain) {
            if (index > plain.size()) throw std::out_of_range("basic_secure_string::substr");
            return basic_secure_string(plain.substr(index, count));
        });
    }
    [[nodiscard]] int compare(string_view_type value) const {
        return with_plaintext([value](string_view_type plain) { return plain.compare(value); });
    }
    [[nodiscard]] size_type find(string_view_type value, size_type index = 0) const {
        return with_plaintext([=](string_view_type plain) { return plain.find(value, index); });
    }
    [[nodiscard]] bool starts_with(string_view_type value) const {
        return with_plaintext([value](string_view_type plain) { return plain.starts_with(value); });
    }
    [[nodiscard]] bool ends_with(string_view_type value) const {
        return with_plaintext([value](string_view_type plain) { return plain.ends_with(value); });
    }

    [[nodiscard]] string_type reveal() const {
        return with_plaintext([](string_view_type plain) { return string_type(plain); });
    }

    template <typename Function>
    decltype(auto) with_plaintext(Function&& function) const {
        detail::plaintext_buffer<CharT> plain(size_);
        decrypt(plain.span());
        return std::invoke(std::forward<Function>(function), plain.view());
    }

    void swap(basic_secure_string& other) noexcept {
        using std::swap;
        swap(encrypted_, other.encrypted_);
        swap(size_, other.size_);
        swap(key_, other.key_);
        swap(nonce_, other.nonce_);
    }

    friend bool operator==(const basic_secure_string& left, string_view_type right) { return left.compare(right) == 0; }
    friend bool operator==(string_view_type left, const basic_secure_string& right) { return right == left; }
    friend bool operator==(const basic_secure_string& left, const CharT* right) { return left == string_view_type(right); }
    friend bool operator==(const CharT* left, const basic_secure_string& right) { return right == left; }
    friend bool operator==(const basic_secure_string& left, const basic_secure_string& right) {
        if (left.size_ != right.size_) return false;
        return left.with_plaintext([&right](string_view_type value) { return right == value; });
    }
    friend std::strong_ordering operator<=>(const basic_secure_string& left, string_view_type right) {
        const int result = left.compare(right);
        return result < 0 ? std::strong_ordering::less : result > 0 ? std::strong_ordering::greater
                                                               : std::strong_ordering::equal;
    }

    friend std::basic_istream<CharT, Traits>& operator>>(std::basic_istream<CharT, Traits>& input, basic_secure_string& value) {
        typename std::basic_istream<CharT, Traits>::sentry sentry(input);
        if (!sentry) return input;

        using temporary_string_type = std::basic_string<CharT, Traits, detail::secure_allocator<CharT>>;
        temporary_string_type buffer;
        struct wipe_guard {
            temporary_string_type& value;
            ~wipe_guard() { detail::secure_wipe(value.data(), value.size() * sizeof(CharT)); }
        } guard{buffer};
        input >> buffer;
        if (input.good() || input.eof()) value.assign(string_view_type(buffer.data(), buffer.size()));
        return input;
    }

    friend std::basic_ostream<CharT, Traits>& operator<<(std::basic_ostream<CharT, Traits>& output, const basic_secure_string& value) {
        typename std::basic_ostream<CharT, Traits>::sentry sentry(output);
        if (!sentry) return output;

        value.with_plaintext([&output](string_view_type plain) {
            output.write(plain.data(), static_cast<std::streamsize>(plain.size()));
        });
        return output;
    }

private:
    static size_type checked_bytes(size_type count) {
        if (count > std::numeric_limits<size_type>::max() / sizeof(CharT)) {
            throw std::length_error("basic_secure_string is too large");
        }
        return count * sizeof(CharT);
    }

    void initialize_key() {
        detail::secure_random(key_);
        key_locked_ = detail::lock_memory(key_.data(), key_.size());
    }
    void initialize_key_noexcept() noexcept {
        try { initialize_key(); }
        catch (...) { std::terminate(); }
    }
    void wipe_ciphertext() noexcept {
        detail::secure_wipe(encrypted_.data(), encrypted_.size());
        encrypted_.clear();
    }
    void encrypt(std::span<const std::byte> plain) {
        std::array<std::byte, 12> new_nonce{};
        detail::secure_random(new_nonce);
        std::vector<std::byte> replacement(plain.size());
        detail::chacha20_xor(plain, replacement, key_, new_nonce);
        wipe_ciphertext();
        encrypted_ = std::move(replacement);
        nonce_ = new_nonce;
    }
    void decrypt(std::span<CharT> output) const noexcept {
        detail::chacha20_xor(encrypted_, std::as_writable_bytes(output), key_, nonce_);
    }
    CharT value_at(size_type index) const {
        CharT value{};
        const auto byte_index = index * sizeof(CharT);
        detail::chacha20_xor(
            std::span(encrypted_).subspan(byte_index, sizeof(CharT)),
            std::as_writable_bytes(std::span(&value, 1)), key_, nonce_, byte_index);
        return value;
    }
    void set(size_type index, CharT value) {
        if (index >= size_) throw std::out_of_range("basic_secure_string::set");
        mutate([=](string_type& plain) { plain[index] = value; });
    }
    template <typename Function>
    void mutate(Function&& function) {
        detail::plaintext_buffer<CharT> buffer(size_);
        decrypt(buffer.span());
        string_type plain(buffer.view());
        struct wipe_guard {
            string_type& value;
            ~wipe_guard() { detail::secure_wipe(value.data(), value.size() * sizeof(CharT)); }
        } guard{plain};
        std::invoke(std::forward<Function>(function), plain);
        assign(plain);
    }

    std::vector<std::byte> encrypted_;
    size_type size_ = 0;
    alignas(64) std::array<std::byte, 32> key_{};
    std::array<std::byte, 12> nonce_{};
    bool key_locked_ = false;
};

using SecureString = basic_secure_string<char>;
using WSecureString = basic_secure_string<wchar_t>;

template <typename CharT, typename Traits>
void swap(basic_secure_string<CharT, Traits>& left, basic_secure_string<CharT, Traits>& right) noexcept {
    left.swap(right);
}

} // namespace cppsecurestring

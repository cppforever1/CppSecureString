// Standard library includes for secure memory management and cryptographic operations
#include <array>
#include <bit>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <unordered_map>

#ifdef _WIN32
#define NOMINMAX
#include <Windows.h>
#include <bcrypt.h>
#else   // POSIX
#include <sys/mman.h>
#include <sys/random.h>
#include <unistd.h>
#endif

#include "cppsecurestring/secure_string.hpp"

namespace cppsecurestring::detail
{
    namespace
    {

        std::mutex locked_pages_mutex;
        std::unordered_map<std::uintptr_t, std::size_t> locked_pages;

        std::size_t page_size() noexcept
        {
#ifdef _WIN32
            SYSTEM_INFO info{};
            GetSystemInfo(&info);
            return info.dwPageSize;
#else
            const long result = ::sysconf(_SC_PAGESIZE);
            return result > 0 ? static_cast<std::size_t>(result) : 4096U;
#endif
        }

        bool platform_lock_page(std::uintptr_t address, std::size_t size) noexcept
        {
#ifdef _WIN32
            return VirtualLock(reinterpret_cast<void *>(address), size) != 0;
#else
            if (::mlock(reinterpret_cast<void *>(address), size) != 0)
                return false;
            (void)::madvise(reinterpret_cast<void *>(address), size, MADV_DONTDUMP);
            return true;
#endif
        }

        void platform_unlock_page(std::uintptr_t address, std::size_t size) noexcept
        {
#ifdef _WIN32
            (void)VirtualUnlock(reinterpret_cast<void *>(address), size);
#else
            (void)::madvise(reinterpret_cast<void *>(address), size, MADV_DODUMP);
            (void)::munlock(reinterpret_cast<void *>(address), size);
#endif
        }

        constexpr std::uint32_t rotate_left(std::uint32_t value, int count) noexcept
        {
            return std::rotl(value, count);
        }

        void quarter_round(std::uint32_t &a, std::uint32_t &b, std::uint32_t &c, std::uint32_t &d) noexcept
        {
            a += b;
            d ^= a;
            d = rotate_left(d, 16);
            c += d;
            b ^= c;
            b = rotate_left(b, 12);
            a += b;
            d ^= a;
            d = rotate_left(d, 8);
            c += d;
            b ^= c;
            b = rotate_left(b, 7);
        }

        std::uint32_t load32(const std::byte *input) noexcept
        {
            return std::to_integer<std::uint32_t>(input[0]) |
                   (std::to_integer<std::uint32_t>(input[1]) << 8) |
                   (std::to_integer<std::uint32_t>(input[2]) << 16) |
                   (std::to_integer<std::uint32_t>(input[3]) << 24);
        }

        void store32(std::byte *output, std::uint32_t value) noexcept
        {
            for (int index = 0; index < 4; ++index)
                output[index] = std::byte(value >> (index * 8));
        }

        void chacha20_block(std::span<const std::byte, 32> key,
                            std::span<const std::byte, 12> nonce,
                            std::uint32_t counter,
                            std::span<std::byte, 64> output) noexcept
        {
            std::array<std::uint32_t, 16> state{
                0x61707865U, 0x3320646eU, 0x79622d32U, 0x6b206574U,
                load32(key.data()), load32(key.data() + 4), load32(key.data() + 8), load32(key.data() + 12),
                load32(key.data() + 16), load32(key.data() + 20), load32(key.data() + 24), load32(key.data() + 28),
                counter, load32(nonce.data()), load32(nonce.data() + 4), load32(nonce.data() + 8)};
            auto working = state;
            for (int round = 0; round < 10; ++round)
            {
                quarter_round(working[0], working[4], working[8], working[12]);
                quarter_round(working[1], working[5], working[9], working[13]);
                quarter_round(working[2], working[6], working[10], working[14]);
                quarter_round(working[3], working[7], working[11], working[15]);
                quarter_round(working[0], working[5], working[10], working[15]);
                quarter_round(working[1], working[6], working[11], working[12]);
                quarter_round(working[2], working[7], working[8], working[13]);
                quarter_round(working[3], working[4], working[9], working[14]);
            }
            for (std::size_t index = 0; index < state.size(); ++index)
            {
                store32(output.data() + index * 4, working[index] + state[index]);
            }
            secure_wipe(working.data(), sizeof(working));
            secure_wipe(state.data(), sizeof(state));
        }

    } // namespace

    void secure_wipe(void *data, std::size_t size) noexcept
    {
        if (data == nullptr || size == 0)
            return;
#ifdef _WIN32
        SecureZeroMemory(data, size);
#else
        volatile auto *bytes = static_cast<volatile unsigned char *>(data);
        while (size-- != 0)
            *bytes++ = 0;
#endif
    }

    void secure_random(std::span<std::byte> output)
    {
#ifdef _WIN32
        if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(output.data()),
                            static_cast<ULONG>(output.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        {
            throw std::runtime_error("BCryptGenRandom failed");
        }
#else
        std::size_t completed = 0;
        while (completed < output.size())
        {
            const auto result = ::getrandom(output.data() + completed, output.size() - completed, 0);
            if (result > 0)
                completed += static_cast<std::size_t>(result);
            else if (result < 0 && errno != EINTR)
                throw std::runtime_error("getrandom failed");
        }
#endif
    }

    bool lock_memory(void *data, std::size_t size) noexcept
    {
        if (data == nullptr || size == 0)
            return true;
        try
        {
            const auto page = page_size();
            const auto start = reinterpret_cast<std::uintptr_t>(data);
            const auto first = start - (start % page);
            const auto last = (start + size - 1) - ((start + size - 1) % page);
            std::scoped_lock lock(locked_pages_mutex);
            for (auto address = first; address <= last; address += page)
            {
                auto found = locked_pages.find(address);
                if (found != locked_pages.end())
                {
                    ++found->second;
                }
                else if (platform_lock_page(address, page))
                {
                    locked_pages.emplace(address, 1);
                }
                else
                {
                    for (auto rollback = first; rollback < address; rollback += page)
                    {
                        auto entry = locked_pages.find(rollback);
                        if (--entry->second == 0)
                        {
                            platform_unlock_page(rollback, page);
                            locked_pages.erase(entry);
                        }
                    }
                    return false;
                }
            }
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    void unlock_memory(void *data, std::size_t size) noexcept
    {
        if (data == nullptr || size == 0)
            return;
        const auto page = page_size();
        const auto start = reinterpret_cast<std::uintptr_t>(data);
        const auto first = start - (start % page);
        const auto last = (start + size - 1) - ((start + size - 1) % page);
        std::scoped_lock lock(locked_pages_mutex);
        for (auto address = first; address <= last; address += page)
        {
            auto found = locked_pages.find(address);
            if (found != locked_pages.end() && --found->second == 0)
            {
                platform_unlock_page(address, page);
                locked_pages.erase(found);
            }
        }
    }

    void chacha20_xor(std::span<const std::byte> input,
                      std::span<std::byte> output,
                      std::span<const std::byte, 32> key,
                      std::span<const std::byte, 12> nonce,
                      std::size_t stream_offset) noexcept
    {
        std::array<std::byte, 64> stream{};
        std::size_t offset = 0;
        std::uint32_t counter = static_cast<std::uint32_t>(stream_offset / stream.size());
        std::size_t block_offset = stream_offset % stream.size();
        while (offset < input.size())
        {
            chacha20_block(key, nonce, counter++, stream);
            const auto count = std::min(stream.size() - block_offset, input.size() - offset);
            for (std::size_t index = 0; index < count; ++index)
            {
                output[offset + index] = input[offset + index] ^ stream[block_offset + index];
            }
            offset += count;
            block_offset = 0;
        }
        secure_wipe(stream.data(), stream.size());
    }

} // namespace cppsecurestring::detail

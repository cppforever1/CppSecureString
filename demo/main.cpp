#include "cppsecurestring/secure_string.hpp"

#include <iostream>
#include <string>
#include <string_view>

int main()
{
    // Create a secure string to store the password
    cppsecurestring::SecureString password;

    std::cout << "Enter a secret: ";

    // Read password using stream extraction without exposing plaintext in memory
    std::cin >> password;

    std::cout << "Stored " << password.size() << " encrypted characters in memory.\n";

    // Display the entered password (still encrypted in memory)
    std::cout << "password entered. " << password << std::endl;

    // Access the plaintext within a controlled scope
    password.with_plaintext([](std::string_view plaintext)
                            { std::cout << "Plaintext is available only inside this callback: " << plaintext << '\n'; });

    // Explicitly reveal the password (use with caution)
    std::string revealed = password.reveal();
    std::cout << "Explicitly revealed copy: " << revealed << '\n';
    cppsecurestring::detail::secure_wipe(revealed.data(), revealed.size());
}

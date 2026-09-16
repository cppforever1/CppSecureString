cmake_minimum_required(VERSION 3.20)

project(CppSecureString VERSION 1.0.0 LANGUAGES CXX)

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

option(CPPSECURESTRING_BUILD_TESTS "Build CppSecureString tests" ON)
option(CPPSECURESTRING_BUILD_DEMO "Build the CppSecureString demo" ON)

add_library(CppSecureString src/secure_memory.cpp)
add_library(CppSecureString::CppSecureString ALIAS CppSecureString)

target_compile_features(CppSecureString PUBLIC cxx_std_20)
target_include_directories(CppSecureString
    PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

if(WIN32)
    target_compile_definitions(CppSecureString PRIVATE CPPSECURESTRING_BUILDING_LIBRARY)
    target_link_libraries(CppSecureString PRIVATE bcrypt)
endif()

if(MSVC)
    target_compile_options(CppSecureString PRIVATE /W4 /permissive-)
else()
    target_compile_options(CppSecureString PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(CPPSECURESTRING_BUILD_DEMO)
    add_subdirectory(demo)
endif()

if(CPPSECURESTRING_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

install(TARGETS CppSecureString
    EXPORT CppSecureStringTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT CppSecureStringTargets
    FILE CppSecureStringTargets.cmake
    NAMESPACE CppSecureString::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/CppSecureString
)

configure_package_config_file(
    cmake/CppSecureStringConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/CppSecureStringConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/CppSecureString
)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/CppSecureStringConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/CppSecureStringConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/CppSecureStringConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/CppSecureString
)

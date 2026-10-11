cmake_minimum_required(VERSION 3.16)
project(VaultixSDK VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(VAULTIX_BUILD_EXAMPLES "Build the example programs" ${PROJECT_IS_TOP_LEVEL})

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

add_library(vaultix_sdk STATIC src/VaultixClient.cpp)
add_library(Vaultix::vaultix_sdk ALIAS vaultix_sdk)

target_include_directories(vaultix_sdk PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
target_link_libraries(vaultix_sdk PUBLIC OpenSSL::SSL OpenSSL::Crypto CURL::libcurl)

if(WIN32)
    # Hardware ID via WMI
    target_link_libraries(vaultix_sdk PUBLIC ole32 oleaut32 wbemuuid)
    if(MSVC)
        target_compile_definitions(vaultix_sdk PRIVATE _CRT_SECURE_NO_WARNINGS)
    endif()
else()
    find_package(Threads REQUIRED)
    target_link_libraries(vaultix_sdk PUBLIC Threads::Threads)
endif()

if(VAULTIX_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

include(GNUInstallDirs)
install(TARGETS vaultix_sdk ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES include/VaultixClient.h include/VaultixSDK.hpp DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

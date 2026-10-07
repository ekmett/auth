# SPDX-FileType: Source
# SPDX-FileCopyrightText: 2026 Edward Kmett <ekmett@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause OR Apache-2.0

cmake_minimum_required(VERSION 3.30)
project(auth VERSION 0.0.1 LANGUAGES CXX)

if(PROJECT_IS_TOP_LEVEL)
  set(CMAKE_CXX_EXTENSIONS OFF)
endif()

option(AUTH_BUILD_TESTS "Build authenticated computation tests" ${PROJECT_IS_TOP_LEVEL})
option(AUTH_BUILD_DOCS "Build API documentation (requires Doxygen)" OFF)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)

add_library(auth STATIC)
add_library(auth::auth ALIAS auth)
target_compile_features(auth PUBLIC cxx_std_26)
target_sources(auth PUBLIC
  FILE_SET modules TYPE CXX_MODULES BASE_DIRS src FILES
    src/auth/error.ccm src/auth/hash.ccm src/auth/serialization.ccm src/auth.ccm)
target_link_libraries(auth PRIVATE OpenSSL::Crypto)

if(AUTH_BUILD_TESTS)
  enable_testing()
  foreach(test IN ITEMS auth-test auth-api-test)
    add_executable(${test} t/${test}.cc)
    target_link_libraries(${test} PRIVATE auth::auth)
    add_test(NAME ${test} COMMAND ${test})
  endforeach()
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    add_executable(auth-no-elision-test t/auth-test.cc)
    target_link_libraries(auth-no-elision-test PRIVATE auth::auth)
    target_compile_options(auth-no-elision-test PRIVATE -fno-elide-constructors)
    target_compile_definitions(auth-no-elision-test PRIVATE AUTH_TEST_NO_ELISION)
    add_test(NAME auth-no-elision-test COMMAND auth-no-elision-test)
  endif()
endif()

if(AUTH_BUILD_DOCS)
  add_subdirectory(doc)
endif()

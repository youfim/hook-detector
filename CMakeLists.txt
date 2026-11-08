cmake_minimum_required(VERSION 3.20)
project(hook_detector VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

file(GLOB_RECURSE SOURCES
    "src/core/*.cpp"
    "src/scanners/*.cpp"
    "src/report/*.cpp"
    "src/main.cpp"
)

file(GLOB_RECURSE HEADERS
    "include/*.h"
)

add_executable(hook_detector ${SOURCES} ${HEADERS})

target_include_directories(hook_detector PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)

target_compile_definitions(hook_detector PRIVATE
    UNICODE
    _UNICODE
)

if(MSVC)
    target_compile_options(hook_detector PRIVATE
        /W4
        /EHsc
        /utf-8
        /permissive-
    )
endif()

target_link_libraries(hook_detector PRIVATE
    Advapi32
    User32
)

set_target_properties(hook_detector PROPERTIES
    OUTPUT_NAME "hook_detector"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_SOURCE_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_SOURCE_DIR}/bin"
)

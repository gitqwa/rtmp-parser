cmake_minimum_required(VERSION 3.10)
project(rtmp_parser CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(rtmp_probe
    src/pcap_reader.cpp
    src/tcp_stream.cpp
    src/chunk_parser.cpp
    src/main.cpp
)
target_include_directories(rtmp_probe PRIVATE src)

if(MSVC)
    target_compile_options(rtmp_probe PRIVATE /utf-8)
endif()

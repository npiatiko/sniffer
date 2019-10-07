cmake_minimum_required(VERSION 3.14)
project(sniff C)

set(CMAKE_C_STANDARD 99)
SET(CMAKE_MODULE_PATH /Users/npiatiko/CLionProjects/untitled1/)
find_package(PCAP REQUIRED)
add_executable(sniff main.c)
target_link_libraries(sniff ${PCAP_LIBRARY})

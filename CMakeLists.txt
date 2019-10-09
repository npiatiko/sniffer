cmake_minimum_required(VERSION 3.14)
project(sniff C)

set(CMAKE_C_STANDARD 99)
SET(CMAKE_MODULE_PATH /home/npiatiko/CLionProjects/sniffer)
find_package(PCAP REQUIRED)
add_executable(sniff main.c sniffex.c get_filter_exp.c main.c)
target_link_libraries(sniff ${PCAP_LIBRARY})

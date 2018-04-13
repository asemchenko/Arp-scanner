cmake_minimum_required(VERSION 3.9)
project(arp_scanner)

set(CMAKE_CXX_STANDARD 11)
add_definitions(-g -ggdb)
set(SOURCE_DIR src/)
add_executable(arp_scanner ${SOURCE_DIR}main.c ${SOURCE_DIR}arpUtils.c)
target_link_libraries(arp_scanner m)
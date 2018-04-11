cmake_minimum_required(VERSION 3.9)
project(arp_scanner)

set(CMAKE_CXX_STANDARD 11)
add_definitions(-g -ggdb)
add_executable(arp_scanner main.c)
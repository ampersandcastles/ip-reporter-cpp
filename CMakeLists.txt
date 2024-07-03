cmake_minimum_required(VERSION 3.5)

project(ip_reporter)

set(CMAKE_CXX_STANDARD 17)

find_package(Qt5Widgets REQUIRED)
find_package(Qt5Core REQUIRED)
find_package(Qt5Gui REQUIRED)
find_package(Qt5Network REQUIRED)

set(CMAKE_AUTOMOC ON)

add_executable(ip_reporter src/main.cpp)

find_package(Threads REQUIRED)
target_link_libraries(ip_reporter PRIVATE Qt5::Widgets Qt5::Core Qt5::Gui Qt5::Network Threads::Threads pcap)

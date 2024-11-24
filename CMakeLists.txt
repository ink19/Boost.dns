cmake_minimum_required(VERSION 3.10)

project(BoostDns)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(Boost_NO_WARN_NEW_VERSIONS ON)

ADD_DEFINITIONS(-DBOOST_LOG_DYN_LINK)
find_package(Boost 1.82.0 COMPONENTS log log_setup system  url REQUIRED)
find_package(c-ares REQUIRED)

add_executable(BoostDns main.cpp)
target_link_libraries(BoostDns ${Boost_LIBRARIES} ${Boost_LOG_SETUP_LIBRARY} ssl crypto c-ares::cares)

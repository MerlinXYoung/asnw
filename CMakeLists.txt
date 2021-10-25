cmake_minimum_required(VERSION 3.15)
project(ASNW)

find_package(CURL REQUIRED)
include_directories(${CURL_INCLUD_DIR})

set(LIBEV_HOME ${CMAKE_CURRENT_SOURCE_DIR}/3rd/libev)
include_directories(${LIBEV_HOME}/include)
link_directories(${LIBEV_HOME}/lib)

set(JEMALLOC_HOME ${CMAKE_CURRENT_SOURCE_DIR}/3rd/jemalloc)
include_directories(${JEMALLOC_HOME}/include)
link_directories(${JEMALLOC_HOME}/lib)


include_directories(${CMAKE_CURRENT_SOURCE_DIR}/asnw)
add_subdirectory(asnw)
add_subdirectory(test)

cmake_minimum_required(VERSION 3.15)
project(3RD)

include(ExternalProject)
include(ProcessorCount)
ProcessorCount(N)
find_program(MAKE_EXE NAMES make)

ExternalProject_Add(libev
    DOWNLOAD_DIR ${CMAKE_SOURCE_DIR}/.downloads
    INSTALL_DIR ${CMAKE_SOURCE_DIR}/libev

    URL http://dist.schmorp.de/libev/libev-4.33.tar.gz
    URL_MD5 a3433f23583167081bf4acdd5b01b34f
    DOWNLOAD_NAME libev-4.33.tar.gz
    TIMEOUT 600
    TLS_VERIFY False
    BUILD_IN_SOURCE True
    CONFIGURE_COMMAND ./configure --prefix=${CMAKE_SOURCE_DIR}/libev
    BUILD_COMMAND ${MAKE_EXE} -j${N}

)

ExternalProject_Add(jemalloc
    DOWNLOAD_DIR ${CMAKE_SOURCE_DIR}/.downloads
    INSTALL_DIR ${CMAKE_SOURCE_DIR}/jemalloc

    URL https://github.com/jemalloc/jemalloc/archive/refs/tags/5.2.1.tar.gz
    URL_MD5 0d627898d4aa58d09ef5d3fdde17dacb
    DOWNLOAD_NAME jemalloc-5.2.1.tar.gz
    TIMEOUT 600
    TLS_VERIFY False
    BUILD_IN_SOURCE True
    CONFIGURE_COMMAND ./autogen.sh && ./configure --prefix=${CMAKE_SOURCE_DIR}/jemalloc
    BUILD_COMMAND ${MAKE_EXE} -j${N}

)
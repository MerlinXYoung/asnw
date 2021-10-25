
file(GLOB SRCS *.c)


foreach(SRC ${SRCS})
    string(REGEX REPLACE ".*/" "" TGT ${SRC})
    string(REPLACE ".c" ".t" TGT ${TGT})
    add_executable(${TGT} ${SRC})
    target_link_libraries(${TGT} nw ev CURL::libcurl jemalloc)
endforeach(SRC SRCS)
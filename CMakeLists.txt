cmake_minimum_required(VERSION 3.3)
project(spinoff_toolkit)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

#boost
FIND_PACKAGE( Boost 1.57 COMPONENTS program_options REQUIRED )

#libbitcoin
set(LIBBITCOIN /nix/store/x7g501xv9inzriw999g2xksfsbzm966d-libbitcoin-2.9.0)

# add in our dependencies
include_directories(include ${LIBBITCOIN}/include ${Boost_INCLUDE_DIR})
link_directories(${LIBBITCOIN}/lib)

#bst library
set(HEADER_FILES
        include/bitcoin/bst/generate.h
)
set(SOURCE_FILES
        ${HEADER_FILES}
        src/generate.cpp
        src/sqlite3.c
        src/key.cpp
)
add_library(spinoff_toolkit SHARED ${SOURCE_FILES})

# test program
set(TEST_SOURCE_FILES
        ${HEADER_FILES}
        src/util/main.cpp
)
add_executable(spinoff_test ${TEST_SOURCE_FILES})
target_link_libraries(spinoff_test bitcoin spinoff_toolkit ${Boost_LIBRARIES})



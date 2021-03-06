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
        include/bitcoin/bst/common.h
        include/bitcoin/bst/generate.h
        include/bitcoin/bst/claim.h
        include/bitcoin/bst/misc.h
)
set(SOURCE_FILES
        ${HEADER_FILES}
        src/common.cpp
        src/generate.cpp
        src/claim.cpp
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

# write snapshot file from existing sqlite
set(WRITE_SNAPSHOT_SOURCE_FILES ${HEADER_FILES} src/util/writeSnapshotFromSql.cpp)

add_executable(write_snapshot ${WRITE_SNAPSHOT_SOURCE_FILES})
target_link_libraries(write_snapshot bitcoin spinoff_toolkit ${Boost_LIBRARIES})

add_executable(get_balance ${HEADER_FILES} src/util/getBalance.cpp)
target_link_libraries(get_balance bitcoin spinoff_toolkit ${Boost_LIBRARIES})

add_executable(print_snapshot ${HEADER_FILES} src/util/printSnapshot.cpp)
target_link_libraries(print_snapshot bitcoin spinoff_toolkit ${Boost_LIBRARIES})


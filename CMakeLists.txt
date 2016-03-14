cmake_minimum_required(VERSION 3.3)
project(spinoff_toolkit)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

#boost
set(BOOST_INCLUDEDIR /nix/store/v14w92dl1iyd6b32lys7d2cmhqxnzn35-boost-1.57.0-dev/include)
set(BOOST_LIBRARYDIR /nix/store/w5pb7nx1al2a7z3ag0f77kw53rgcyklj-boost-1.57.0-lib/lib)
FIND_PACKAGE( Boost 1.57 COMPONENTS program_options REQUIRED )

#libbitcoin
set(LIBBITCOIN /nix/store/x7g501xv9inzriw999g2xksfsbzm966d-libbitcoin-2.9.0)

#libsecp256k1
set(LIBSECP /nix/store/1f9wnbxz4khdw1vsdslpdvi5a7dp4hqs-secp256k1-version3/include)


# add in our dependencies
include_directories(include ${LIBSECP} ${Boost_INCLUDE_DIR})

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


cmake_minimum_required(VERSION 3.3)
project(spinoff_toolkit)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

#boost
FIND_PACKAGE( Boost 1.57 COMPONENTS program_options REQUIRED )

#libbitcoin
set(LIBBITCOIN /nix/store/x7g501xv9inzriw999g2xksfsbzm966d-libbitcoin-2.9.0)
include_directories(${LIBBITCOIN}/include ${Boost_INCLUDE_DIR})
link_directories(${LIBBITCOIN}/lib)

set(SOURCE_FILES main.cpp)
add_executable(spinoff_toolkit ${SOURCE_FILES})
target_link_libraries(spinoff_toolkit bitcoin ${Boost_LIBRARIES})
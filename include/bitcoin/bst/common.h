/**
 * Copyright (C) 2015 Bitcoin Spinoff Toolkit developers
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef SPINOFF_TOOLKIT_COMMON_H
#define SPINOFF_TOOLKIT_COMMON_H

#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>

using namespace std;

namespace bst {
    static const string SNAPSHOT_NAME = "snapshot";
    static const string SNAPSHOT_CLAIMED_NAME = "snapshot.claimed";

    // std::array seems a problem, not sure why. Find out and switch these
    typedef std::vector<uint8_t> uint160_t;
    typedef std::vector<uint8_t> uint256_t;

    /*
    Version            01 00 00 00                                                 4 bytes (uint32)
    Blockhash          hash of Bitcoin block that snapshot was taken from          32 bytes
    nP2PKH             the number of P2PKH to be claimed                           8 bytes (uint64)
     */
    struct snapshot_header {
        uint32_t version;
        uint256_t block_hash;
        uint64_t nP2PKH;
        uint64_t nP2SH;

        snapshot_header() : version(0), block_hash(32), nP2PKH(0), nP2SH(0) { }
    };
    static const int HEADER_SIZE = 4 + 32 + 8 + 8;

    void resetClaims(snapshot_header& header);
}

#endif
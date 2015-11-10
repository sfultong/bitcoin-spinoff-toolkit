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
#include "bitcoin/bst/common.h"
#include <bitcoin/bitcoin.hpp>

using namespace std;

namespace bst {

    void resetClaims(snapshot_header& header)
    {
        uint64_t totalClaims = header.nP2PKH + header.nP2SH;
        uint64_t bytesToWrite;
        if (totalClaims % 8) {
            bytesToWrite = totalClaims / 8 + 1;
        } else {
            bytesToWrite = totalClaims / 8;
        }
        ofstream claimedDatabase;
        claimedDatabase.open(SNAPSHOT_CLAIMED_NAME, ios::binary);
        char zeroByte = 0;
        for (uint64_t i = 0; i < bytesToWrite; i++)
        {
            claimedDatabase.write(&zeroByte, 1);
        }
        claimedDatabase.close();
    }
}

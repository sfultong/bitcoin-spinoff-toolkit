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
#ifndef SPINOFF_TOOLKIT_GENERATE_H
#define SPINOFF_TOOLKIT_GENERATE_H

#include <fstream>
#include <sqlite3.h>
#include "common.h"

using namespace std;

namespace bst {

    struct snapshot_preparer {
        sqlite3 *db;
        sqlite3_stmt *insert_p2pkh;
        sqlite3_stmt *get_all_p2pkh;
        sqlite3_stmt *insert_p2sh;
        sqlite3_stmt *get_all_p2sh;
        uint8_t address_prefix;
        int transaction_count;
        bool debug;
    };

    bool prepareForUTXOs(snapshot_preparer& preparer);
    bool writeUTXO(snapshot_preparer& preparer, const uint160_t& pubkeyscript, const uint64_t amount);
    // also cleans up
    bool writeSnapshot(snapshot_preparer& preparer, const uint256_t& blockhash, const uint64_t dustLimit);
    bool writeJustSqlite(snapshot_preparer& preparer);
    bool writeSnapshotFromSqlite(const uint256_t& blockhash, const uint64_t dustLimit);

}

#endif //SPINOFF_TOOLKIT_GENERATE_H

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

#include <iostream>
#include <bitcoin/bitcoin.hpp>
#include "bitcoin/bst/generate.h"

using namespace std;

int main() {

    vector<uint8_t> block_hash = vector<uint8_t>(32);
    bst::writeSnapshotFromSqlite(block_hash, 0);

    return 0;

}

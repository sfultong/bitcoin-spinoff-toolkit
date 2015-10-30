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
#ifndef SPINOFF_TOOLKIT_CLAIM_H
#define SPINOFF_TOOLKIT_CLAIM_H

#include <fstream>
#include "common.h"

using namespace std;

namespace bst {

    struct snapshot_reader
    {
        ifstream snapshot;
        snapshot_header header;
    };

    bool openSnapshot(snapshot_reader& reader);

    void printSnapshot();

    uint64_t getP2PKHAmount(snapshot_reader& reader, const string& claim, const uint256_t& signature);
    uint64_t getP2PKHAmount(snapshot_reader& reader, const string& claim, const string& signature);
    uint64_t getP2SHAmount(snapshot_reader& reader, const string& transaction, const string& address, const uint32_t input_index);
}

#endif

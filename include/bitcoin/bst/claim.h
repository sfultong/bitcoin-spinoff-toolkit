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
        ifstream* snapshot;
        snapshot_header header;

        snapshot_reader() {}
        snapshot_reader(const snapshot_reader& other) {
            snapshot = other.snapshot;
            header = other.header;
        }
    };

    class SnapshotEntryCollection {
    public:
        SnapshotEntryCollection(const snapshot_reader& _reader, int64_t _amount, uint64_t _offset, uint64_t _claimed_offset) {
            reader = _reader;
            amount = _amount;
            offset = _offset;
            claimed_offset = _claimed_offset;
        }
        void getEntry(int64_t index, snapshot_entry& entry) const;
        bool getEntry(const uint256_t& hash, snapshot_entry& entry);
        bool getEntry(const string& claim, const string& signature, snapshot_entry& entry);
        bool getEntry(const string& claim, const uint256_t signature, snapshot_entry& entry);
        void setClaimed(int64_t index);
        snapshot_reader reader;
        int64_t amount;
        uint64_t offset;
        uint64_t claimed_offset;
    };

    bool openSnapshot(ifstream& stream, snapshot_reader& reader);

    SnapshotEntryCollection getP2PKHCollection(const snapshot_reader& reader);
    SnapshotEntryCollection getP2SHCollection(const snapshot_reader& reader);

    void printSnapshot();

    uint64_t getP2PKHAmount(SnapshotEntryCollection& collection, const string& claim, const string& signature);
    uint64_t getP2SHAmount(SnapshotEntryCollection& collection, const string& transaction, const string& address, const uint32_t input_index);
}

#endif

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

#include "bitcoin/bst/claim.h"
#include "bitcoin/bst/misc.h"
#include "bitcoin/bst/common.h"

using namespace std;

namespace bst {

    bool openSnapshot(ifstream& stream, snapshot_reader& reader)
    {
        reader.snapshot = &stream;
        stream.read(reinterpret_cast<char*>(&reader.header.version), sizeof(reader.header.version));
        stream.read(reinterpret_cast<char*>(&reader.header.block_hash[0]), 32);
        stream.read(reinterpret_cast<char*>(&reader.header.nP2PKH), sizeof(reader.header.nP2PKH));
        stream.read(reinterpret_cast<char*>(&reader.header.nP2SH), sizeof(reader.header.nP2SH));
        return true;
    }

    // assumes the vectors are the same length
    int compare (const vector<uint8_t>& one, const vector<uint8_t>& two)
    {
        for (long int i = 0; i < one.size(); i++)
        {
            if (one[i] < two[i]) return -1;
            if (one[i] > two[i]) return 1;
        }
        return 0;
    }

    int64_t getIndex(snapshot_reader &reader, const vector<uint8_t>& address, int64_t high, uint64_t base_offset)
    {
        int64_t low = 0;
        while (low <= high) {
            int64_t mid = (low + high) / 2;
            uint64_t offset = base_offset + mid * 28;
            reader.snapshot->seekg(offset);

            vector<uint8_t> hashVec(20);
            reader.snapshot->read(reinterpret_cast<char *>(&hashVec[0]), 20);

            int comparison = compare(address, hashVec);
            if (comparison == 0) {
                return mid;
            }
            if (comparison < 0) {
                high = mid - 1;
            } else {
                low = mid + 1;
            }
        }

        // not found
        return -1;
    }

    bool getClaimed(int64_t index, uint64_t offset)
    {
        uint64_t claimIndex = index + offset;
        ifstream claimedFile(SNAPSHOT_CLAIMED_NAME, ios::binary);
        claimedFile.seekg(claimIndex / 8, ios::beg);
        char byte;
        int bitSet = 1 << (claimIndex % 8);
        claimedFile.read(&byte, 1);
        claimedFile.close();
        return (byte & bitSet) != 0;
    }

    void setClaimedWithOffset(int64_t index, uint64_t offset)
    {
        fstream claimedFile(SNAPSHOT_CLAIMED_NAME, ios::in | ios::out | ios::binary);
        int64_t bitOffset = index + offset;
        claimedFile.seekg(bitOffset / 8, ios::beg);
        char byte;
        int bitSet = 1 << (bitOffset % 8);
        claimedFile.read(&byte, 1);
        byte |= bitSet;

        claimedFile.seekg(bitOffset / 8, ios::beg);
        claimedFile.write(&byte, 1);
        claimedFile.close();
    }

    void SnapshotEntryCollection::getEntry(int64_t index, snapshot_entry& entry) const {
        entry.index = index;
        reader.snapshot->seekg(offset + index * 28);
        reader.snapshot->read(reinterpret_cast<char*>(&entry.hash[0]), 20);
        reader.snapshot->read(reinterpret_cast<char*>(&entry.amount), sizeof(amount));
        entry.claimed = getClaimed(index, claimed_offset);
    }

    bool SnapshotEntryCollection::getEntry(const uint256_t& hash, snapshot_entry& entry) {
        int64_t index = getIndex(reader, hash, amount, offset);
        if (index < 0) return false;

        getEntry(index, entry);
        return true;
    }

    void SnapshotEntryCollection::setClaimed(int64_t index) {
        setClaimedWithOffset(index, claimed_offset);
    }

    SnapshotEntryCollection getP2PKHCollection(const snapshot_reader& reader) {
        SnapshotEntryCollection collection = SnapshotEntryCollection(reader, reader.header.nP2PKH, HEADER_SIZE, 0);
        return collection;
    }

    SnapshotEntryCollection getP2SHCollection(const snapshot_reader& reader) {
        uint64_t offset = HEADER_SIZE + reader.header.nP2PKH * 28;
        SnapshotEntryCollection collection = SnapshotEntryCollection(reader, reader.header.nP2SH, offset, reader.header.nP2PKH);
        return collection;
    }

    uint64_t getP2PKHAmount(SnapshotEntryCollection& collection, const string &claim, const string &signature) {

        snapshot_entry entry;
        if ( collection.getEntry(claim, signature, entry) ) {
            return entry.amount;
        }
        return 0;
    }
}

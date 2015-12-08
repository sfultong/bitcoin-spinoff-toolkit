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

#include <bitcoin/bitcoin.hpp>
#include "bitcoin/bst/claim.h"
#include "bitcoin/bst/misc.h"
#include "bitcoin/bst/common.h"

using namespace std;

namespace bst {

    bool openSnapshot(ifstream& stream, snapshot_reader& reader)
    {
        reader.snapshot = &stream;
        stream.open(SNAPSHOT_NAME, ios::binary);
        if (! stream.is_open())
        {
            return false;
        }
        stream.read(reinterpret_cast<char*>(&reader.header.version), sizeof(reader.header.version));
        stream.read(reinterpret_cast<char*>(&reader.header.block_hash[0]), 32);
        stream.read(reinterpret_cast<char*>(&reader.header.nP2PKH), sizeof(reader.header.nP2PKH));
        stream.read(reinterpret_cast<char*>(&reader.header.nP2SH), sizeof(reader.header.nP2SH));
        return true;
    }

    void printSnapshot()
    {
        ifstream stream;
        snapshot_reader reader;
        openSnapshot(stream, reader);

        cout << "p2pkh:" << endl;
        SnapshotEntryCollection p2pkhEntries = getP2PKHCollection(reader);
        for (SnapshotEntryCollection::const_iterator i = p2pkhEntries.begin(); i != p2pkhEntries.end(); i++) {
            snapshot_entry entry = *i;
            bc::short_hash sh;
            copy(entry.hash.begin(), entry.hash.end(), sh.begin());
            bc::payment_address address(111, sh);
            cout << address.encoded() << " " << entry.amount << endl;
        }

        cout << "p2sh:" << endl;
        SnapshotEntryCollection p2shEntries = getP2SHCollection(reader);
        for (SnapshotEntryCollection::const_iterator i = p2shEntries.begin(); i != p2shEntries.end(); i++) {
            snapshot_entry entry = *i;
            bc::short_hash sh;
            copy(entry.hash.begin(), entry.hash.end(), sh.begin());
            bc::payment_address address(196, sh);
            cout << address.encoded() << " " << entry.amount << endl;
        }

        reader.snapshot->close();
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

    bool getEntry (SnapshotEntryCollection& entries, const string &claim, const bc::message_signature &signature, snapshot_entry& entry) {

        // first, get p2pkh value for claim
        vector<uint8_t> claimVector = vector<uint8_t>(20);
        if (!recover_address(claim, signature, claimVector)) {
            false;
        }

        return entries.getEntry(claimVector, entry);
    }

    bool SnapshotEntryCollection::getEntry(const string& claim, const string& signature, snapshot_entry& entry) {
        bc::message_signature decodedSignature = bc::message_signature();
        bc::data_chunk chunk;
        if (!bc::decode_base64(chunk, signature)) return false;
        copy(chunk.begin(), chunk.end(), decodedSignature.begin());

        return bst::getEntry(*this, claim, decodedSignature, entry);
    }

    bool SnapshotEntryCollection::getEntry(const string& claim, const uint256_t signature, snapshot_entry& entry) {
        bc::message_signature message_signature = bc::message_signature();
        copy(signature.begin(), signature.end(), message_signature.begin());

        return bst::getEntry(*this, claim, message_signature, entry);
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

    uint64_t getP2SHAmount(SnapshotEntryCollection& collection, const string &transaction, const string &address,
                           const uint32_t input_index) {
        bc::payment_address payment_address = bc::payment_address(address);
        vector <uint8_t> claimVector = vector<uint8_t>(payment_address.hash().begin(), payment_address.hash().end());

        // construct output script from script hash
        vector <uint8_t> output_vector = vector<uint8_t>(23);
        copy(claimVector.begin(), claimVector.end(), output_vector.begin() + 2);
        output_vector[0] = (uint8_t) bc::opcode::hash160;
        output_vector[1] = 0x14; // special - 20 bytes of data follow
        output_vector[22] = (uint8_t) bc::opcode::equal;
        bc::array_slice <uint8_t> output_slice(output_vector);
        bc::script_type output_script = bc::parse_script(output_slice);

        // construct transaction
        bc::data_chunk transaction_chunk;
        bc::decode_base16(transaction_chunk, transaction);
        bc::transaction_type transaction_type;
        bc::satoshi_load(transaction_chunk.begin(), transaction_chunk.end(), transaction_type);
        bc::script_type input_script = transaction_type.inputs[input_index].script;

        // if transaction validates against output script, find amount in snapshot
        if (output_script.run(input_script, transaction_type, input_index)) {
            snapshot_entry entry;
            if ( collection.getEntry(claimVector, entry)) {
                return entry.amount;
            }
        }
        return 0;
    }

}

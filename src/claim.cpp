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

    bool openSnapshot(snapshot_reader& reader)
    {
        reader.snapshot.open(SNAPSHOT_NAME, ios::binary);
        reader.snapshot.read(reinterpret_cast<char*>(&reader.header.version), sizeof(reader.header.version));
        reader.snapshot.read(reinterpret_cast<char*>(&reader.header.block_hash[0]), 32);
        reader.snapshot.read(reinterpret_cast<char*>(&reader.header.nP2PKH), sizeof(reader.header.nP2PKH));
        reader.snapshot.read(reinterpret_cast<char*>(&reader.header.nP2SH), sizeof(reader.header.nP2SH));
    }

    void printSnapshot()
    {
        snapshot_reader reader;
        openSnapshot(reader);

        cout << "p2pkh:" << endl;
        for (int i = 0; i < reader.header.nP2PKH; i++) {
            vector<uint8_t> hashVec(20);
            reader.snapshot.read(reinterpret_cast<char*>(&hashVec[0]), 20);
            bc::short_hash sh;
            copy(hashVec.begin(), hashVec.end(), sh.begin());
            bc::payment_address address(111, sh);

            uint64_t amount;
            reader.snapshot.read(reinterpret_cast<char*>(&amount), sizeof(amount));
            cout << address.encoded() << " " << amount << endl;
        }

        cout << "p2sh:" << endl;
        for (int i = 0; i < reader.header.nP2SH; i++) {
            vector<uint8_t> hashVec(20);
            reader.snapshot.read(reinterpret_cast<char*>(&hashVec[0]), 20);
            bc::short_hash sh;
            copy(hashVec.begin(), hashVec.end(), sh.begin());
            bc::payment_address address(196, sh);

            uint64_t amount;
            reader.snapshot.read(reinterpret_cast<char*>(&amount), sizeof(amount));
            cout << address.encoded() << " " << amount << endl;
        }

        reader.snapshot.close();
        remove(SNAPSHOT_NAME.c_str());
    }

    // assumes the vectors are the same length
    int compare (vector<uint8_t>& one, vector<uint8_t>& two)
    {
        for (long int i = 0; i < one.size(); i++)
        {
            if (one[i] < two[i]) return -1;
            if (one[i] > two[i]) return 1;
        }
        return 0;
    }

    uint64_t getP2PKHAmount(snapshot_reader &reader, const string &claim, const bc::message_signature &signature) {

        // first, get p2pkh value for claim
        vector <uint8_t> claimVector = vector<uint8_t>(20);
        if (!recover_address(claim, signature, claimVector)) {
            return 0;
        }

        uint64_t low = 0;
        uint64_t high = reader.header.nP2PKH;
        while (low <= high) {
            uint64_t mid = (low + high) / 2;
            uint64_t offset = HEADER_SIZE + mid * 28;
            reader.snapshot.seekg(offset);

            vector <uint8_t> hashVec(20);
            reader.snapshot.read(reinterpret_cast<char *>(&hashVec[0]), 20);

            int comparison = compare(claimVector, hashVec);
            if (comparison == 0) {
                uint64_t amount;
                reader.snapshot.read(reinterpret_cast<char *>(&amount), sizeof(amount));
                return amount;
            }
            if (comparison < 0) {
                high = mid - 1;
            } else {
                low = mid + 1;
            }
        }
        return 0;
    }

    uint64_t getP2PKHAmount(snapshot_reader &reader, const string &claim, const string &signature) {
        // convert signature string from base64
        bc::message_signature decodedSignature = bc::message_signature();
        bc::data_chunk chunk;
        if (!bc::decode_base64(chunk, signature)) return 0;

        // copy
        copy(chunk.begin(), chunk.end(), decodedSignature.begin());

        return getP2PKHAmount(reader, claim, decodedSignature);
    }

    uint64_t getP2PKHAmount(snapshot_reader &reader, const string &claim, const uint256_t &signature) {

        bc::message_signature message_signature = bc::message_signature();
        copy(signature.begin(), signature.end(), message_signature.begin());
        return getP2PKHAmount(reader, claim, message_signature);
    }

    uint64_t getP2SHAmount(snapshot_reader &reader, const string &transaction, const string &address,
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
            uint64_t low = 0;
            uint64_t high = reader.header.nP2SH;
            while (low <= high) {
                uint64_t mid = (low + high) / 2;
                uint64_t offset = HEADER_SIZE + reader.header.nP2PKH * 28 + mid * 28;
                reader.snapshot.seekg(offset);

                vector <uint8_t> hashVec(20);
                reader.snapshot.read(reinterpret_cast<char *>(&hashVec[0]), 20);

                int comparison = compare(claimVector, hashVec);
                if (comparison == 0) {
                    uint64_t amount;
                    reader.snapshot.read(reinterpret_cast<char *>(&amount), sizeof(amount));
                    return amount;
                }
                if (comparison < 0) {
                    high = mid - 1;
                } else {
                    low = mid + 1;
                }
            }
        }
        return 0;
    }

}

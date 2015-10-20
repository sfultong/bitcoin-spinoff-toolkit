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

using namespace std;

namespace bst {

    typedef std::vector<uint8_t> short_hash;
    typedef std::vector<uint8_t> sha_hash;

    /*
    Version            01 00 00 00                                                 4 bytes (uint32)
    Blockhash          hash of Bitcoin block that snapshot was taken from          32 bytes
    nP2PKH             the number of P2PKH to be claimed                           8 bytes (uint64)
     */
    struct snapshot_header {
        uint32_t version;
        sha_hash block_hash;
        uint64_t nP2PKH;
        uint64_t nP2SH;

        snapshot_header() : version(0), block_hash(32), nP2PKH(0), nP2SH(0) { }
    };

    struct snapshot_preparer {
        sqlite3 *db;
        sqlite3_stmt *insert_p2pkh;
        sqlite3_stmt *get_all_p2pkh;
        sqlite3_stmt *insert_p2sh;
        sqlite3_stmt *get_all_p2sh;
        uint8_t address_prefix;
        int transaction_count;
    };

    struct snapshot_reader
    {
        ifstream snapshot;
        snapshot_header header;
    };

    string getVerificationMessage(string address, string message, string signature);
    bool prepareForUTXOs(snapshot_preparer& preparer);
    bool writeUTXO(snapshot_preparer& preparer, const vector<uint8_t>& pubkeyscript, const uint64_t amount);
    // also cleans up
    bool writeSnapshot(snapshot_preparer& preparer, const vector<uint8_t>& blockhash);
    void prettyPrintVector(const vector<uint8_t>& vector, stringstream& ss);
    bool decodeVector(const string& vectorString, vector<uint8_t>& vector);
    void printSnapshot();
    bool openSnapshot(snapshot_reader& reader);

    bool recover_address(const string& message, const string& signature, vector<uint8_t>& paymentVector);
    uint64_t getP2PKHAmount(snapshot_reader& reader, const string& claim, const string& signature);
    uint64_t getP2SHAmount(snapshot_reader& reader, const string& transaction, const string& address, const int input_index);

}

#endif //SPINOFF_TOOLKIT_GENERATE_H

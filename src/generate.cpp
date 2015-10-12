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
#include "bitcoin/bst/generate.h"
#include "sqlite3.h"

using namespace std;

namespace bst {
    static const string VERIFIED = "wow, we verified this";
    static const string UNMATCHED = "signature doesn't match";
    static const string INVALID_SIGNATURE = "signature invalid encoding";
    static const string INVALID_ADDRESS = "Invalid Address";
    static const string DB_NAME = "temp.sqlite";
    static const string SNAPSHOT_NAME = "snapshot";
    static const int TRANSACTION_SIZE = 1000;

    string getVerificationMessage(string address, string message, string signature)
    {
        bc::payment_address payment_address;

        if (payment_address.set_encoded(address)) {
            bc::message_signature decodedSignature;
            bc::data_chunk chunk;
            if (bc::decode_base64(chunk, signature)) {
                copy(chunk.begin(), chunk.end(), decodedSignature.begin());
                vector<uint8_t> messageBytes(message.begin(),message.end());
                bc::array_slice<uint8_t> slice(messageBytes);
                if (bc::verify_message(slice, address, decodedSignature)) {
                    return VERIFIED;
                } else {
                    return UNMATCHED;
                }
            } else {
                return INVALID_SIGNATURE;
            }
        } else {
            return INVALID_ADDRESS;
        }
    }

    static int callback(void *NotUsed, int argc, char **argv, char **azColName){
        int i;
        const char **safeArgv = const_cast<const char**>(argv);
        for(i=0; i<argc; i++){
            printf("%s = %s\n", azColName[i], argv[i] ? safeArgv[i] : "NULL");
        }
        printf("\n");
        return 0;
    }

    static const string CREATE_TABLE = "create table p2pkh ("
                "pkh char(20) primary key,"
                "amount integer"
                ");";
    static const string INSERT_P2PKH = "insert into p2pkh values (?, ?)";
    static const string GET_ALL_P2PKH = "select * from p2pkh order by pkh";
    bool prepareForUTXOs(snapshot_preparer& preparer)
    {
        preparer.transaction_count = 0;
        char *zErrMsg = 0;
        int rc;

        rc = sqlite3_open(DB_NAME.c_str(), &preparer.db);
        if( rc ){
            fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(preparer.db));
            sqlite3_close(preparer.db);
            return false;
        }

        rc = sqlite3_exec(preparer.db, CREATE_TABLE.c_str(), callback, 0, &zErrMsg);
        if( rc!=SQLITE_OK ){
            fprintf(stderr, "SQL error: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
            return false;
        }

        sqlite3_prepare_v2(preparer.db, INSERT_P2PKH.c_str(), -1, &preparer.insert_p2pkh, NULL);
        sqlite3_prepare_v2(preparer.db, GET_ALL_P2PKH.c_str(), -1, &preparer.get_all_p2pkh, NULL);
        return true;
    }

    void prettyPrintVector(const vector<uint8_t>& vector, stringstream& stream)
    {
        for (auto &b : vector)
        {
            int first = (b & 0xF0) >> 4;
            first = first < 10 ? first + '0' : first - 10 + 'A';
            int second = b & 0x0F;
            second = second < 10 ? second + '0' : second - 10 + 'A';
            stream << (char) first << (char) second;
        }
    }

    void printVector(const vector<uint8_t>& vector)
    {
        stringstream ss;
        prettyPrintVector(vector, ss);
        cout << ss.str() << endl;
    }

    bool decodeVector(const string& vectorString, vector<uint8_t>& vector)
    {
        if (vectorString.length() % 2)
        {
            return false;
        }
        for (int i = 0; i < vectorString.length(); i+=2)
        {
            int first = vectorString[i];
            if (first >= 'a' && first <= 'f') first += 'A' - 'a';
            if (! ((first >= '0' && first <= '9')
                || (first >= 'A' && first <= 'F'))) return false;
            int value = first >= 'A' ? first - 'A' + 10 : first - '0';
            value <<= 4;

            int second = vectorString[i + 1];
            if (second >= 'a' && second <= 'f') second += 'A' - 'a';
            if (! ((second >= '0' && second <= '9')
                || (second >= 'A' && second <= 'F'))) return false;
            value += second >= 'A' ? second - 'A' + 10 : second - '0';

            vector.push_back((uint8_t) value);
        }
        return true;
    }

    bool writeUTXO(snapshot_preparer& preparer, const vector<uint8_t>& pubkeyscript, const uint64_t amount)
    {
        int rc;
        char *zErrMsg = 0;

        // start transaction if we haven't already
        if (preparer.transaction_count == 0) {
            string begin = "BEGIN;";
            rc = sqlite3_exec(preparer.db, begin.c_str(), callback, 0, &zErrMsg);
            if( rc!=SQLITE_OK ){
                fprintf(stderr, "SQL error: %s\n", zErrMsg);
                sqlite3_free(zErrMsg);
            }
        }

        bc::array_slice<uint8_t> slice(pubkeyscript);
        bc::script_type script = bc::parse_script(slice);
        switch (script.type())
        {
            case bc::payment_type::pubkey:
                break;
            case bc::payment_type::pubkey_hash:
            {
                /*
                stringstream ss;
                prettyPrintVector(pubkeyscript, ss);
                cout << ss.str() << " " << amount << endl;
                 */

                vector<uint8_t>::const_iterator keystart = pubkeyscript.begin() + 3;
                vector<uint8_t>::const_iterator keyend = pubkeyscript.begin() + 23;
                vector<uint8_t> key(keystart, keyend);
                stringstream ss;
                prettyPrintVector(key, ss);
                string keyString = ss.str();
                rc = sqlite3_bind_text(preparer.insert_p2pkh, 1, keyString.c_str(), -1, NULL);
                if (rc != SQLITE_OK)
                {
                    cout << "error binding address hash " << rc << endl;
                    return false;
                }
                rc = sqlite3_bind_int64(preparer.insert_p2pkh, 2, amount);
                if (rc != SQLITE_OK)
                {
                    cout << "error binding amount" << rc << endl;
                    return false;
                }
                rc = sqlite3_step(preparer.insert_p2pkh);
                if (rc != SQLITE_DONE)
                {
                    cout << "error writing row " << rc << endl;
                    return false;
                }
                rc = sqlite3_reset(preparer.insert_p2pkh);
                if (rc != SQLITE_OK)
                {
                    cout << "error resetting prepared statement" << rc << endl;
                    return false;
                }
            }
                break;
            case bc::payment_type::multisig:
                break;
            case bc::payment_type::script_hash:
                break;
            default:
                break;
        }

        // finish a transaction if we've reached the statement limit
        preparer.transaction_count++;
        if (preparer.transaction_count == TRANSACTION_SIZE)
        {
            string commit = "COMMIT;";
            rc = sqlite3_exec(preparer.db, commit.c_str(), callback, 0, &zErrMsg);
            if( rc!=SQLITE_OK ){
                fprintf(stderr, "SQL error: %s\n", zErrMsg);
                sqlite3_free(zErrMsg);
            }
            preparer.transaction_count = 0;
        }

        return true;
    }

    bool writeSnapshot(snapshot_preparer& preparer)
    {
        char *zErrMsg = 0;
        int rc;

        // commit the last transaction, if there is one
        if (preparer.transaction_count != 0)
        {
            string commit = "COMMIT;";
            rc = sqlite3_exec(preparer.db, commit.c_str(), callback, 0, &zErrMsg);
            if( rc!=SQLITE_OK ){
                fprintf(stderr, "SQL error: %s\n", zErrMsg);
                sqlite3_free(zErrMsg);
            }
            preparer.transaction_count = 0;
        }

        // get total number of p2pkh transactions
        snapshot_header header = snapshot_header();
        sqlite3_stmt* stmt;
        string get_total_p2pkh = "select count(*) from p2pkh;";
        rc = sqlite3_prepare_v2(preparer.db, get_total_p2pkh.c_str(), -1, &stmt, NULL);
        rc = sqlite3_step(stmt);
        header.nP2PKH = sqlite3_column_int64(stmt, 0);
        rc = sqlite3_finalize(stmt);

        // write snapshot header
        ofstream snapshot;
        snapshot.open(SNAPSHOT_NAME, ios::binary);
        snapshot.write(reinterpret_cast<const char*>(&header.version), sizeof(header.version));
        copy(header.block_hash.begin(), header.block_hash.end(), ostream_iterator<uint8_t>(snapshot));
        snapshot.write(reinterpret_cast<const char*>(&header.nP2PKH), sizeof(header.nP2PKH));

        // write all p2pkh to snapshot
        rc = sqlite3_prepare_v2(preparer.db, GET_ALL_P2PKH.c_str(), -1, &stmt, NULL);
        if( rc!=SQLITE_OK ){
            cout << "Could not prepare statement for getting all p2pkh" << endl;
        }

        while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {

            const unsigned char* keyCString = sqlite3_column_text(stmt, 0);
            stringstream ss;
            ss << keyCString;
            vector<uint8_t> hashVec;
            if ( ! decodeVector(ss.str(), hashVec))
            {
                cout << "error decoding " << ss.str() << endl;
                return 0;
            }
            copy(hashVec.begin(), hashVec.end(), ostream_iterator<uint8_t>(snapshot));

            uint64_t amount = sqlite3_column_int64(stmt, 1);
            snapshot.write(reinterpret_cast<const char*>(&amount), sizeof(amount));
        }

        if (SQLITE_DONE != rc)
        {
            cout << "could not get all rows: " << rc << endl;
        }

        sqlite3_close(preparer.db);

        remove(DB_NAME.c_str());

        snapshot.flush();
        snapshot.close();

        return true;
    }

    void printSnapshot()
    {
        snapshot_header header;
        ifstream snapshot;
        snapshot.open(SNAPSHOT_NAME, ios::binary);
        snapshot.read(reinterpret_cast<char*>(&header.version), sizeof(header.version));
        snapshot.read(reinterpret_cast<char*>(&header.block_hash[0]), 20);
        snapshot.read(reinterpret_cast<char*>(&header.nP2PKH), sizeof(header.nP2PKH));

        for (int i = 0; i < header.nP2PKH; i++) {
            vector<uint8_t> hashVec(20);
            snapshot.read(reinterpret_cast<char*>(&hashVec[0]), 20);
            bc::short_hash sh;
            copy(hashVec.begin(), hashVec.end(), sh.begin());
            bc::payment_address address(111, sh);

            uint64_t amount;
            snapshot.read(reinterpret_cast<char*>(&amount), sizeof(amount));
            cout << address.encoded() << " " << amount << endl;
        }

        snapshot.close();
        remove(SNAPSHOT_NAME.c_str());
    }
}


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
    static const int TRANSACTION_SIZE = 1000;
    static const string CREATE_P2PKH_TABLE = "create table p2pkh ("
            "id integer primary key,"
            "pkh char(20),"
            "amount integer"
            ");";
    static const string CREATE_P2SH_TABLE = "create table p2sh ("
            "id integer primary key,"
            "sh char(20),"
            "amount integer"
            ");";

    static const string CREATE_P2PKH_INDEX = "create index p2pkh_pkh on p2pkh (pkh);";
    static const string CREATE_P2SH_INDEX = "create index p2sh_sh on p2sh (sh);";
    static const string INSERT_P2PKH = "insert into p2pkh (pkh, amount) values (?, ?)";
    static const string INSERT_P2SH = "insert into p2sh (sh, amount) values (?, ?)";
    static const string GET_ALL_P2PKH = "select pkh, total from"
            " (select pkh, sum(amount) as total from p2pkh group by pkh order by pkh)"
            "where total >= ?";
    static const string GET_ALL_P2SH = "select sh, total from"
            " (select sh, sum(amount) as total from p2sh group by sh order by sh)"
            "where total >= ?";

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

        rc = sqlite3_exec(preparer.db, CREATE_P2PKH_TABLE.c_str(), callback, 0, &zErrMsg);
        if( rc!=SQLITE_OK ){
            fprintf(stderr, "SQL error: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
            return false;
        }

        rc = sqlite3_exec(preparer.db, CREATE_P2PKH_INDEX.c_str(), callback, 0, &zErrMsg);
        if( rc!=SQLITE_OK ){
            fprintf(stderr, "SQL error: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
            return false;
        }

        rc = sqlite3_exec(preparer.db, CREATE_P2SH_TABLE.c_str(), callback, 0, &zErrMsg);
        if( rc!=SQLITE_OK ){
            fprintf(stderr, "SQL error: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
            return false;
        }

        rc = sqlite3_exec(preparer.db, CREATE_P2SH_INDEX.c_str(), callback, 0, &zErrMsg);
        if( rc!=SQLITE_OK ){
            fprintf(stderr, "SQL error: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
            return false;
        }

        sqlite3_prepare_v2(preparer.db, INSERT_P2PKH.c_str(), -1, &preparer.insert_p2pkh, NULL);
        sqlite3_prepare_v2(preparer.db, GET_ALL_P2PKH.c_str(), -1, &preparer.get_all_p2pkh, NULL);
        sqlite3_prepare_v2(preparer.db, INSERT_P2SH.c_str(), -1, &preparer.insert_p2sh, NULL);
        sqlite3_prepare_v2(preparer.db, GET_ALL_P2SH.c_str(), -1, &preparer.get_all_p2sh, NULL);
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
        string keyString;
        sqlite3_stmt* insert;

        try {
            bc::script_type script = bc::parse_script(slice);

            switch (script.type())
            {
                case bc::payment_type::pubkey:
                case bc::payment_type::pubkey_hash:
                {
                    if (preparer.debug)
                    {
                        string transactionString = bc::encode_base16(slice);
                        cout << "recording p2pkh transaction " << transactionString << endl;
                    }

                    insert = preparer.insert_p2pkh;
                    bc::payment_address paymentAddress;
                    if (bc::extract(paymentAddress, script))
                    {
                        stringstream ss;
                        vector<uint8_t> short_hash = vector<uint8_t>(20);
                        copy(paymentAddress.hash().begin(), paymentAddress.hash().end(), short_hash.begin());
                        prettyPrintVector(short_hash, ss);
                        keyString = ss.str();
                    } else {
                        cout << "could not get a payment address from script" << endl;
                        return false;
                    }
                }
                    break;
                case bc::payment_type::script_hash:
                {
                    if (preparer.debug)
                    {
                        string transactionString = bc::encode_base16(slice);
                        cout << "recording p2sh transaction " << transactionString << endl;
                    }

                    insert = preparer.insert_p2sh;
                    bc::payment_address paymentAddress;
                    if (bc::extract(paymentAddress, script))
                    {
                        keyString = bc::encode_base16(paymentAddress.hash());
                    } else {
                        cout << "could not get a payment address from script" << endl;
                        return false;
                    }
                }
                    break;
                default:
                {
                    if (preparer.debug)
                    {
                        string transactionString = bc::encode_base16(slice);
                        cout << "recording strange transaction " << transactionString << endl;
                    }

                    // treat all non-standard transactions as P2SH
                    insert = preparer.insert_p2sh;
                    bc::short_hash hash = bc::bitcoin_short_hash(slice);
                    keyString = bc::encode_base16(hash);
                }
                    break;
            }

            rc = sqlite3_bind_text(insert, 1, keyString.c_str(), -1, NULL);
            if (rc != SQLITE_OK)
            {
                cout << "error binding address hash " << rc << endl;
                return false;
            }
            rc = sqlite3_bind_int64(insert, 2, amount);
            if (rc != SQLITE_OK)
            {
                cout << "error binding amount" << rc << endl;
                return false;
            }
            rc = sqlite3_step(insert);
            if (rc != SQLITE_DONE)
            {
                cout << "error writing row " << rc << endl;
                return false;
            }
            rc = sqlite3_reset(insert);
            if (rc != SQLITE_OK)
            {
                cout << "error resetting prepared statement" << rc << endl;
                return false;
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

        } catch (bc::end_of_stream) {
            cout << "could not parse transaction script" << endl;
            return false;
        }
    }

    bool writeJustSqlite(snapshot_preparer& preparer)
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
                return false;
            }
            preparer.transaction_count = 0;
        }

        sqlite3_finalize(preparer.insert_p2pkh);
        sqlite3_finalize(preparer.insert_p2sh);
        sqlite3_finalize(preparer.get_all_p2pkh);
        sqlite3_finalize(preparer.get_all_p2sh);

        rc = sqlite3_close(preparer.db);
        if( rc!=SQLITE_OK ){
            fprintf(stderr, "SQL error: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
            return false;
        }

        return true;
    }

    bool writeSnapshotFromSqlite(const uint256_t& blockhash, const uint64_t dustLimit)
    {
        sqlite3 *db;
        char *zErrMsg = 0;
        int rc;

        rc = sqlite3_open(DB_NAME.c_str(), &db);
        if( rc ){
            fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
            sqlite3_close(db);
            return false;
        }

        snapshot_header header = snapshot_header();
        ofstream snapshot;
        snapshot.open(SNAPSHOT_NAME, ios::binary);

        // write all p2pkh to snapshot
        sqlite3_stmt* stmt;
        snapshot.seekp(HEADER_SIZE);
        rc = sqlite3_prepare_v2(db, GET_ALL_P2PKH.c_str(), -1, &stmt, NULL);
        if( rc!=SQLITE_OK ){
            cout << "Could not prepare statement for getting all p2pkh " << rc << endl;
        }

        rc = sqlite3_bind_int64(stmt, 1, dustLimit);
        if (rc != SQLITE_OK)
        {
            cout << "error binding dust limit" << rc << endl;
            return false;
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
            header.nP2PKH++;
        }

        if (SQLITE_DONE != rc)
        {
            cout << "could not get all p2pkh rows: " << rc << endl;
        }
        rc = sqlite3_finalize(stmt);

        // write all p2sh to snapshot
        rc = sqlite3_prepare_v2(db, GET_ALL_P2SH.c_str(), -1, &stmt, NULL);
        if( rc!=SQLITE_OK ){
            cout << "Could not prepare statement for getting all p2sh" << endl;
        }

        rc = sqlite3_bind_int64(stmt, 1, dustLimit);
        if (rc != SQLITE_OK)
        {
            cout << "error binding dust limit" << rc << endl;
            return false;
        }

        while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {

            const unsigned char* keyCString = sqlite3_column_text(stmt, 0);
            stringstream ss;
            ss << keyCString;
            bc::data_chunk chunk;

            if ( ! bc::decode_base16(chunk, ss.str()))
            {
                cout << "error decoding " << ss.str() << endl;
                return 0;
            }
            copy(chunk.begin(), chunk.end(), ostream_iterator<uint8_t>(snapshot));

            uint64_t amount = sqlite3_column_int64(stmt, 1);
            snapshot.write(reinterpret_cast<const char*>(&amount), sizeof(amount));
            header.nP2SH++;
        }

        if (SQLITE_DONE != rc)
        {
            cout << "could not get all p2sh rows: " << rc << endl;
        }
        rc = sqlite3_finalize(stmt);

        sqlite3_close(db);

        // write snapshot header
        snapshot.seekp(0);
        snapshot.write(reinterpret_cast<const char*>(&header.version), sizeof(header.version));
        copy(header.block_hash.begin(), header.block_hash.end(), ostream_iterator<uint8_t>(snapshot));
        snapshot.write(reinterpret_cast<const char*>(&header.nP2PKH), sizeof(header.nP2PKH));
        snapshot.write(reinterpret_cast<const char*>(&header.nP2SH), sizeof(header.nP2SH));

        snapshot.flush();
        snapshot.close();

        // write claim bitfield file
        resetClaims(header);

        return true;
    }

    bool writeSnapshot(snapshot_preparer& preparer, const vector<uint8_t>& blockhash, const uint64_t dustLimit)
    {
        bool result = writeJustSqlite(preparer)
            && writeSnapshotFromSqlite(blockhash, dustLimit);
        // on success, clean up
        if (result) {
            remove(DB_NAME.c_str());
        }
        return result;
    }
}


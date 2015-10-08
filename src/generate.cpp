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

/*
  a8ab62c82a3500bee23fa30b26c1c9165dbb423d
 "                                        ";
 */
using namespace std;

namespace bst {
    static const string VERIFIED = "wow, we verified this";
    static const string UNMATCHED = "signature doesn't match";
    static const string INVALID_SIGNATURE = "signature invalid encoding";
    static const string INVALID_ADDRESS = "Invalid Address";
    static const string DB_NAME = "test.sqlite";

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

    void prettyKey(string& s, const vector<uint8_t>& key)
    {
        for (int i = 0; i < 20; i++)
        {
            uint8_t b = key[i];
            int first = (b & 0xF0) >> 4;
            first = first < 10 ? first + '0' : first + 'A';
            int second = b & 0x0F;
            second = second < 10 ? second + '0' : second + 'A';
            /*
            s[2 * i] = first;
            s[2 * i + 1] = second;
             */
            s.replace(2 * i, 1, 1, (char) first);
            s.replace(2 * i + 1, 1, 1, (char) second);
        }
    }

    void prettyPrintVector(const vector<uint8_t>& vector)
    {
        for (auto &b : vector)
        {
            int first = (b & 0xF0) >> 4;
            first = first < 10 ? first + '0' : first + 'A';
            int second = b & 0x0F;
            second = second < 10 ? second + '0' : second + 'A';
            cout << (char) first << (char) second;
        }
    }

    bool writeUTXO(const snapshot_preparer& preparer, const vector<uint8_t>& pubkeyscript, const uint64_t amount)
    {
        int rc;
        bc::array_slice<uint8_t> slice(pubkeyscript);
        bc::script_type script = bc::parse_script(slice);
        switch (script.type())
        {
            case bc::payment_type::pubkey:
                break;
            case bc::payment_type::pubkey_hash:
            {
                vector<uint8_t>::const_iterator keystart = pubkeyscript.begin() + 3;
                vector<uint8_t>::const_iterator keyend = pubkeyscript.begin() + 22;
                vector<uint8_t> key(keystart, keyend);
                string keyString = "                                        ";
                prettyKey(keyString, key);
                sqlite3_bind_text(preparer.insert_p2pkh, 1, keyString.c_str(), -1, NULL);
                sqlite3_bind_int64(preparer.insert_p2pkh, 2, amount);
                rc = sqlite3_step(preparer.insert_p2pkh);
                if (rc != SQLITE_OK)
                {
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
        return true;
    }

    bool writeSnapshot(const snapshot_preparer& preparer)
    {
        char *zErrMsg = 0;
        int rc;
        rc = sqlite3_exec(preparer.db, GET_ALL_P2PKH.c_str(), callback, 0, &zErrMsg);
        if( rc!=SQLITE_OK ){
            fprintf(stderr, "SQL error: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
        }

        sqlite3_close(preparer.db);

        remove(DB_NAME.c_str());

        return true;
    }
}


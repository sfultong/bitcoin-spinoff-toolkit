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
    static const string TEST_STRING = "Things are successful";

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

    string getTest()
    {
        return TEST_STRING;
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

    void testSqlite(ostream& stream)
    {
        sqlite3 *db;
        char *zErrMsg = 0;
        int rc;

        rc = sqlite3_open("test.sqlite", &db);
        if( rc ){
          fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
          sqlite3_close(db);
          return;
        }

        char *createTable = "create table p2pkh ("
                "pkh char(20) primary key,"
                "amount integer"
                ");";
        rc = sqlite3_exec(db, createTable, callback, 0, &zErrMsg);
        if( rc!=SQLITE_OK ){
          fprintf(stderr, "SQL error: %s\n", zErrMsg);
          sqlite3_free(zErrMsg);
        }

        char *insertData = "insert into p2pkh values ("
                "'a8ab62c82a3500bee23fa30b26c1c9165dbb423d',"
                "5"
                ");";
        rc = sqlite3_exec(db, insertData, callback, 0, &zErrMsg);
        if( rc!=SQLITE_OK ){
            fprintf(stderr, "SQL error: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
        }

        char *selectData = "select * from p2pkh;";
        rc = sqlite3_exec(db, selectData, callback, 0, &zErrMsg);
        if( rc!=SQLITE_OK ){
            fprintf(stderr, "SQL error: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
        }



        //rc = sqlite3_prepare_v2(db, )
        /*
        if( rc!=SQLITE_OK ){
            fprintf(stderr, "SQL error: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
        }
         */



        sqlite3_close(db);
    }
}


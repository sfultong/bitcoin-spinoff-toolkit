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

#include <iostream>
#include <sstream>
#include <bits/stream_iterator.h>
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


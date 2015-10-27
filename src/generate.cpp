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
    static const string GET_ALL_P2PKH = "select pkh, sum(amount) from p2pkh group by pkh order by pkh";
    static const string GET_ALL_P2SH = "select sh, sum(amount) from p2sh group by sh order by sh";
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

                bc::payment_address paymentAddress;
                if (bc::extract(paymentAddress, script))
                {
                    stringstream ss;
                    vector<uint8_t> short_hash = vector<uint8_t>(20);
                    copy(paymentAddress.hash().begin(), paymentAddress.hash().end(), short_hash.begin());
                    prettyPrintVector(short_hash, ss);
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
            }
                break;
            case bc::payment_type::script_hash:
            {
                if (preparer.debug)
                {
                    string transactionString = bc::encode_base16(slice);
                    cout << "recording p2sh transaction " << transactionString << endl;
                }

                bc::payment_address paymentAddress;
                if (bc::extract(paymentAddress, script))
                {
                    string keyString = bc::encode_base16(paymentAddress.hash());
                    rc = sqlite3_bind_text(preparer.insert_p2sh, 1, keyString.c_str(), -1, NULL);
                    if (rc != SQLITE_OK)
                    {
                        cout << "error binding address hash " << rc << endl;
                        return false;
                    }
                    rc = sqlite3_bind_int64(preparer.insert_p2sh, 2, amount);
                    if (rc != SQLITE_OK)
                    {
                        cout << "error binding amount" << rc << endl;
                        return false;
                    }
                    rc = sqlite3_step(preparer.insert_p2sh);
                    if (rc != SQLITE_DONE)
                    {
                        cout << "error writing row " << rc << endl;
                        return false;
                    }
                    rc = sqlite3_reset(preparer.insert_p2sh);
                    if (rc != SQLITE_OK)
                    {
                        cout << "error resetting prepared statement" << rc << endl;
                        return false;
                    }
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
                bc::short_hash hash = bc::bitcoin_short_hash(slice);
                string keyString = bc::encode_base16(hash);
                rc = sqlite3_bind_text(preparer.insert_p2sh, 1, keyString.c_str(), -1, NULL);
                if (rc != SQLITE_OK)
                {
                    cout << "error binding address hash " << rc << endl;
                    return false;
                }
                rc = sqlite3_bind_int64(preparer.insert_p2sh, 2, amount);
                if (rc != SQLITE_OK)
                {
                    cout << "error binding amount" << rc << endl;
                    return false;
                }
                rc = sqlite3_step(preparer.insert_p2sh);
                if (rc != SQLITE_DONE)
                {
                    cout << "error writing row " << rc << endl;
                    return false;
                }
                rc = sqlite3_reset(preparer.insert_p2sh);
                if (rc != SQLITE_OK)
                {
                    cout << "error resetting prepared statement" << rc << endl;
                    return false;
                }
            }
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

    bool writeSnapshot(snapshot_preparer& preparer, const vector<uint8_t>& blockhash)
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
        copy(blockhash.begin(), blockhash.end(), header.block_hash.begin());
        sqlite3_stmt* stmt;
        string get_total_p2pkh = "select count(distinct pkh) from p2pkh;";
        rc = sqlite3_prepare_v2(preparer.db, get_total_p2pkh.c_str(), -1, &stmt, NULL);
        rc = sqlite3_step(stmt);
        header.nP2PKH = sqlite3_column_int64(stmt, 0);
        rc = sqlite3_finalize(stmt);

        // get total number of p2sh transactions
        string get_total_p2sh = "select count(distinct sh) from p2sh;";
        rc = sqlite3_prepare_v2(preparer.db, get_total_p2sh.c_str(), -1, &stmt, NULL);
        rc = sqlite3_step(stmt);
        header.nP2SH = sqlite3_column_int64(stmt, 0);
        rc = sqlite3_finalize(stmt);

        // write snapshot header
        ofstream snapshot;
        snapshot.open(SNAPSHOT_NAME, ios::binary);
        snapshot.write(reinterpret_cast<const char*>(&header.version), sizeof(header.version));
        copy(header.block_hash.begin(), header.block_hash.end(), ostream_iterator<uint8_t>(snapshot));
        snapshot.write(reinterpret_cast<const char*>(&header.nP2PKH), sizeof(header.nP2PKH));
        snapshot.write(reinterpret_cast<const char*>(&header.nP2SH), sizeof(header.nP2SH));

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
            cout << "could not get all p2pkh rows: " << rc << endl;
        }
        rc = sqlite3_finalize(stmt);

        // write all p2sh to snapshot
        rc = sqlite3_prepare_v2(preparer.db, GET_ALL_P2SH.c_str(), -1, &stmt, NULL);
        if( rc!=SQLITE_OK ){
            cout << "Could not prepare statement for getting all p2sh" << endl;
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
        }

        if (SQLITE_DONE != rc)
        {
            cout << "could not get all p2sh rows: " << rc << endl;
        }
        rc = sqlite3_finalize(stmt);

        sqlite3_close(preparer.db);

        remove(DB_NAME.c_str());

        snapshot.flush();
        snapshot.close();

        return true;
    }

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

    uint64_t getP2PKHAmount(snapshot_reader& reader, const string& claim, const string& signature)
    {
        // first, get p2pkh value for claim
        vector<uint8_t> claimVector = vector<uint8_t>(20);
        if (! recover_address(claim, signature, claimVector))
        {
            return 0;
        }

        uint64_t low = 0;
        uint64_t high = reader.header.nP2PKH;
        while (low <= high)
        {
            uint64_t mid = (low + high) / 2;
            uint64_t offset = HEADER_SIZE + mid * 28;
            reader.snapshot.seekg(offset);

            vector<uint8_t> hashVec(20);
            reader.snapshot.read(reinterpret_cast<char*>(&hashVec[0]), 20);

            int comparison = compare(claimVector, hashVec);
            if (comparison == 0)
            {
                uint64_t amount;
                reader.snapshot.read(reinterpret_cast<char*>(&amount), sizeof(amount));
                return amount;
            }
            if (comparison < 0)
            {
                high = mid - 1;
            } else {
                low = mid + 1;
            }
        }
        return 0;
    }

    uint64_t getP2SHAmount(snapshot_reader& reader, const string& transaction, const string& address, const uint32_t input_index)
    {
        bc::payment_address payment_address = bc::payment_address(address);
        vector<uint8_t> claimVector = vector<uint8_t>(payment_address.hash().begin(), payment_address.hash().end());

        // construct output script from script hash
        vector<uint8_t> output_vector = vector<uint8_t>(23);
        copy(claimVector.begin(), claimVector.end(), output_vector.begin() + 2);
        output_vector[0] = (uint8_t) bc::opcode::hash160;
        output_vector[1] = 0x14; // special - 20 bytes of data follow
        output_vector[22] = (uint8_t) bc::opcode::equal;
        bc::array_slice<uint8_t> output_slice(output_vector);
        bc::script_type output_script = bc::parse_script(output_slice);

        // construct transaction
        bc::data_chunk transaction_chunk;
        bc::decode_base16(transaction_chunk, transaction);
        bc::transaction_type transaction_type;
        bc::satoshi_load(transaction_chunk.begin(), transaction_chunk.end(), transaction_type);
        bc::script_type input_script = transaction_type.inputs[input_index].script;

        // if transaction validates against output script, find amount in snapshot
        if ( output_script.run(input_script, transaction_type, input_index))
        {
            uint64_t low = 0;
            uint64_t high = reader.header.nP2SH;
            while (low <= high) {
                uint64_t mid = (low + high) / 2;
                uint64_t offset = HEADER_SIZE + reader.header.nP2PKH * 28 + mid * 28;
                reader.snapshot.seekg(offset);

                vector<uint8_t> hashVec(20);
                reader.snapshot.read(reinterpret_cast<char*>(&hashVec[0]), 20);

                int comparison = compare(claimVector, hashVec);
                if (comparison == 0)
                {
                    uint64_t amount;
                    reader.snapshot.read(reinterpret_cast<char*>(&amount), sizeof(amount));
                    return amount;
                }
                if (comparison < 0)
                {
                    high = mid - 1;
                } else {
                    low = mid + 1;
                }
            }
        }
        return 0;
    }
}


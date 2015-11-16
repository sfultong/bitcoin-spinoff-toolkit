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
#include <bitcoin/bitcoin.hpp>
#include "bitcoin/bst/generate.h"
#include "bitcoin/bst/claim.h"
#include "bitcoin/bst/misc.h"

using namespace std;

void test_signing_check()
{
    string testEncodedAddress = "15BWWGJRtB8Z9NXmMAp94whujUK6SrmRwT";
    string messageToSign = "hey there";
    string signatureString = "HxXI251uSorWtrqkZejCljYlU+6s861evqN6u3IyYJVSaqYooYzvuSCf6TA0B+wJDOkqljz0fQgkvKjJHiBJgRg=";

    string expected = "wow, we verified this";
    string result = bst::getVerificationMessage(testEncodedAddress, messageToSign, signatureString);
    if (result != expected)
    {
        cout << "test_signing_check---" << endl;
        cout << "expected: " << expected << endl;
        cout << "result  : " << result << endl;
    }
}

void test_recover_signature()
{
    string testEncodedAddress = "15BWWGJRtB8Z9NXmMAp94whujUK6SrmRwT";
    string messageToSign = "hey there";
    string signatureString = "HxXI251uSorWtrqkZejCljYlU+6s861evqN6u3IyYJVSaqYooYzvuSCf6TA0B+wJDOkqljz0fQgkvKjJHiBJgRg=";

    vector<uint8_t> paymentVector = vector<uint8_t>(20);
    bool result = bst::recover_address(messageToSign, signatureString, paymentVector);
    if (! result)
    {
        cout << "test_recover_signature---" << endl;
        cout << "failed to recover address" << endl;
    }
    bc::short_hash sh;
    copy(paymentVector.begin(), paymentVector.end(), sh.begin());
    bc::payment_address address(0, sh);
    string recoveredAddress = address.encoded();
    if (testEncodedAddress != recoveredAddress)
    {
        cout << "test_recover_signature---" << endl;
        cout << "expected: " << testEncodedAddress << endl;
        cout << "result:   " << recoveredAddress << endl;
    }
}

// only really tests libbitcoin, ignore
void test_address_encoding()
{
    string short_hash = "992fa68a35e9706f5ce12036803df00ff3003dc6";
    vector<uint8_t> hashVec;
    bst::decodeVector(short_hash, hashVec);
    bc::short_hash sh;
    copy(hashVec.begin(), hashVec.end(), sh.begin());
    bc::payment_address address(111, sh);
    cout << address.encoded();
}

void test_store_p2pkhs()
{
    string transaction1 = "76A9142345FBB2B00E115C98C1D6E975C99B5431DE9CDE88AC";
    string transaction2 = "76A914992FA68A35E9706F5CE12036803DF00FF3003DC688AC";
    vector<uint8_t> vector1;
    vector<uint8_t> vector2;
    bst::decodeVector(transaction1, vector1);
    bst::decodeVector(transaction2, vector2);

    bst::snapshot_preparer preparer;
    bst::prepareForUTXOs(preparer);
    bst::writeUTXO(preparer, vector1, 24900000000);
    bst::writeUTXO(preparer, vector2, 99998237);
    vector<uint8_t> block_hash = vector<uint8_t>(32);
    bst::writeSnapshot(preparer, block_hash, 0);
    bst::printSnapshot();
}

void test_store_p2pkhs_and_p2sh()
{
    string transaction1 = "76A9142345FBB2B00E115C98C1D6E975C99B5431DE9CDE88AC";
    string transaction2 = "a91489a16fbc4929fc7c83ada40641411c09fe4b76d887";
    vector<uint8_t> vector1;
    vector<uint8_t> vector2;
    bst::decodeVector(transaction1, vector1);
    bst::decodeVector(transaction2, vector2);

    bst::snapshot_preparer preparer;
    bst::prepareForUTXOs(preparer);
    bst::writeUTXO(preparer, vector1, 10);
    bst::writeUTXO(preparer, vector2, 20);
    vector<uint8_t> block_hash = vector<uint8_t>(32);
    bst::writeSnapshot(preparer, block_hash, 0);
    bst::printSnapshot();
}

void test_store_and_claim()
{
    string transaction1 = "76A9142345FBB2B00E115C98C1D6E975C99B5431DE9CDE88AC";
    string transaction2 = "76A914992FA68A35E9706F5CE12036803DF00FF3003DC688AC";
    string transaction3 = "2102f91ca5628d8a77fbf8e12fd098fdd871bdcb61c84cc3abf111a747b26ff6a2cbac";
    string transaction4 = "a91489a16fbc4929fc7c83ada40641411c09fe4b76d887";
    vector<uint8_t> vector1;
    vector<uint8_t> vector2;
    vector<uint8_t> vector3;
    vector<uint8_t> vector4;
    bst::decodeVector(transaction1, vector1);
    bst::decodeVector(transaction2, vector2);
    bst::decodeVector(transaction3, vector3);
    bst::decodeVector(transaction4, vector4);
    bst::snapshot_preparer preparer;
    preparer.debug = false;
    bst::prepareForUTXOs(preparer);
    bst::writeUTXO(preparer, vector1, 24900000000);
    bst::writeUTXO(preparer, vector2, 99998237);
    bst::writeUTXO(preparer, vector3, 5000000643);
    bst::writeUTXO(preparer, vector4, 123456);
    vector<uint8_t> block_hash = vector<uint8_t>(32);
    bst::writeSnapshot(preparer, block_hash, 0);
    string claim = "I claim funds.";
    string signature = "Hxc0sSkslD2mFE3HtHzIDRqSutQBiAQ+TxrsgVPeL3jWbXtcusuD77MTX7Tc/hJsQtVrbZsf9xpSDs+6Khx7nNk=";
    string signature2 = "H3ys4y9vnG2cvneZMo33Vvv1kQTKr2iCcBZZe78OFl8VaPbXYNwLVTtTh5K7Qu4MpdOQiVo+6SHq6pPSzdBm7PQ=";
    string signature3 = "IIuXyLFeU+HVJnv9TPAGXnCnc0bCOi+enwjIWxsO5FmaMdVNBcRrkYGB07Qbdkghd+0XhnaUL3O+X+h4dzb0Kio=";

    bst::snapshot_reader reader;
    bst::openSnapshot(reader);
    uint64_t expected = 24900000000;
    uint64_t amount = bst::getP2PKHAmount(reader, claim, signature);
    if (amount != expected)
    {
        cout << "test_store_and_claim--- 1" << endl;
        cout << "expected: " << expected << endl;
        cout << "result  : " << amount << endl;
    }
    expected = 99998237;
    amount = bst::getP2PKHAmount(reader, claim, signature2);
    if (amount != expected)
    {
        cout << "test_store_and_claim--- 2" << endl;
        cout << "expected: " << expected << endl;
        cout << "result  : " << amount << endl;
    }
    expected = 5000000643;
    amount = bst::getP2PKHAmount(reader, claim, signature3);
    if (amount != expected)
    {
        cout << "test_store_and_claim--- 3" << endl;
        cout << "expected: " << expected << endl;
        cout << "result  : " << amount << endl;
    }

    // now for the p2sh finale
    string transaction_string = "0100000001a9dd2ae0a5d513a336a2c61db3472e260443eb79ffbd07e154829574c1fa2f3901000000fc00"
            "473044022062b5798436e9524c267f5c03c0601743db0cd3e57722c87a48a51d3af4089ccc02200f00f9e244e1fc6fa8141a4e90fa"
            "43b0423d5eda7a1d6d9eb6f6a375337ceda30147304402204ae544e90a9cdf70db7a571cc44a7dcdc0c9f5cbffea6172d7d8ef625d"
            "ea0758022074c3fa6437c60a762dd49075d80855eec78ea27fafff5e78fb70e07985c9f833014c69522102f91ca5628d8a77fbf8e1"
            "2fd098fdd871bdcb61c84cc3abf111a747b26ff6a2cb2103b708d33d5452ce8232fe096220ad2aaea4aa68ce0f0869e6321e93c88c"
            "f5ce082103917f030d239db795047bb5eb66713838221134e103eee2da5619c0cd938e6f6953aeffffffff0170c9fa020000000019"
            "76a914f2f5bbdea2763591bb5c7552df7d6fe46204bc7588ac00000000";
    string p2sh_address = "2N5nwxNF6Fe91RPExcwcaqPPpV14CSo9cEc";
    expected = 123456;
    amount = bst::getP2SHAmount(reader, transaction_string, p2sh_address, 0);
    if (amount != expected)
    {
        cout << "test_store_and_claim--- 4" << endl;
        cout << "expected: " << expected << endl;
        cout << "result  : " << amount << endl;
    }
}

void test_write_sql_and_snapshot_separately()
{
    string transaction1 = "76A9142345FBB2B00E115C98C1D6E975C99B5431DE9CDE88AC";
    string transaction2 = "76A914992FA68A35E9706F5CE12036803DF00FF3003DC688AC";
    string transaction3 = "2102f91ca5628d8a77fbf8e12fd098fdd871bdcb61c84cc3abf111a747b26ff6a2cbac";
    string transaction4 = "a91489a16fbc4929fc7c83ada40641411c09fe4b76d887";
    vector<uint8_t> vector1;
    vector<uint8_t> vector2;
    vector<uint8_t> vector3;
    vector<uint8_t> vector4;
    bst::decodeVector(transaction1, vector1);
    bst::decodeVector(transaction2, vector2);
    bst::decodeVector(transaction3, vector3);
    bst::decodeVector(transaction4, vector4);
    bst::snapshot_preparer preparer;
    preparer.debug = false;
    bst::prepareForUTXOs(preparer);
    bst::writeUTXO(preparer, vector1, 24900000000);
    bst::writeUTXO(preparer, vector2, 99998237);
    bst::writeUTXO(preparer, vector3, 5000000643);
    bst::writeUTXO(preparer, vector4, 123456);
    vector<uint8_t> block_hash = vector<uint8_t>(32);
    bst::writeJustSqlite(preparer);
    bst::writeSnapshotFromSqlite(block_hash, 0);
    string claim = "I claim funds.";
    string signature = "Hxc0sSkslD2mFE3HtHzIDRqSutQBiAQ+TxrsgVPeL3jWbXtcusuD77MTX7Tc/hJsQtVrbZsf9xpSDs+6Khx7nNk=";
    string signature2 = "H3ys4y9vnG2cvneZMo33Vvv1kQTKr2iCcBZZe78OFl8VaPbXYNwLVTtTh5K7Qu4MpdOQiVo+6SHq6pPSzdBm7PQ=";
    string signature3 = "IIuXyLFeU+HVJnv9TPAGXnCnc0bCOi+enwjIWxsO5FmaMdVNBcRrkYGB07Qbdkghd+0XhnaUL3O+X+h4dzb0Kio=";

    bst::snapshot_reader reader;
    bst::openSnapshot(reader);
    uint64_t expected = 24900000000;
    uint64_t amount = bst::getP2PKHAmount(reader, claim, signature);
    if (amount != expected)
    {
        cout << "test_write_sql_and_snapshot_separately--- 1" << endl;
        cout << "expected: " << expected << endl;
        cout << "result  : " << amount << endl;
    }
    expected = 99998237;
    amount = bst::getP2PKHAmount(reader, claim, signature2);
    if (amount != expected)
    {
        cout << "test_write_sql_and_snapshot_separately--- 2" << endl;
        cout << "expected: " << expected << endl;
        cout << "result  : " << amount << endl;
    }
    expected = 5000000643;
    amount = bst::getP2PKHAmount(reader, claim, signature3);
    if (amount != expected)
    {
        cout << "test_write_sql_and_snapshot_separately--- 3" << endl;
        cout << "expected: " << expected << endl;
        cout << "result  : " << amount << endl;
    }

    // now for the p2sh finale
    string transaction_string = "0100000001a9dd2ae0a5d513a336a2c61db3472e260443eb79ffbd07e154829574c1fa2f3901000000fc00"
            "473044022062b5798436e9524c267f5c03c0601743db0cd3e57722c87a48a51d3af4089ccc02200f00f9e244e1fc6fa8141a4e90fa"
            "43b0423d5eda7a1d6d9eb6f6a375337ceda30147304402204ae544e90a9cdf70db7a571cc44a7dcdc0c9f5cbffea6172d7d8ef625d"
            "ea0758022074c3fa6437c60a762dd49075d80855eec78ea27fafff5e78fb70e07985c9f833014c69522102f91ca5628d8a77fbf8e1"
            "2fd098fdd871bdcb61c84cc3abf111a747b26ff6a2cb2103b708d33d5452ce8232fe096220ad2aaea4aa68ce0f0869e6321e93c88c"
            "f5ce082103917f030d239db795047bb5eb66713838221134e103eee2da5619c0cd938e6f6953aeffffffff0170c9fa020000000019"
            "76a914f2f5bbdea2763591bb5c7552df7d6fe46204bc7588ac00000000";
    string p2sh_address = "2N5nwxNF6Fe91RPExcwcaqPPpV14CSo9cEc";
    expected = 123456;
    amount = bst::getP2SHAmount(reader, transaction_string, p2sh_address, 0);
    if (amount != expected)
    {
        cout << "test_write_sql_and_snapshot_separately--- 4" << endl;
        cout << "expected: " << expected << endl;
        cout << "result  : " << amount << endl;
    }

    // cleanup
    remove("temp.sqlite");
}

void test_dust_pruning()
{
    string transaction1 = "76A9142345FBB2B00E115C98C1D6E975C99B5431DE9CDE88AC";
    string transaction2 = "76A914992FA68A35E9706F5CE12036803DF00FF3003DC688AC";
    vector<uint8_t> vector1;
    vector<uint8_t> vector2;
    bst::decodeVector(transaction1, vector1);
    bst::decodeVector(transaction2, vector2);
    bst::snapshot_preparer preparer;
    preparer.debug = false;
    bst::prepareForUTXOs(preparer);
    bst::writeUTXO(preparer, vector1, 50000);
    bst::writeUTXO(preparer, vector1, 80000);
    bst::writeUTXO(preparer, vector2, 60000);
    vector<uint8_t> block_hash = vector<uint8_t>(32);
    bst::writeSnapshot(preparer, block_hash, 100000);
    string claim = "I claim funds.";
    string signature = "Hxc0sSkslD2mFE3HtHzIDRqSutQBiAQ+TxrsgVPeL3jWbXtcusuD77MTX7Tc/hJsQtVrbZsf9xpSDs+6Khx7nNk=";
    string signature2 = "H3ys4y9vnG2cvneZMo33Vvv1kQTKr2iCcBZZe78OFl8VaPbXYNwLVTtTh5K7Qu4MpdOQiVo+6SHq6pPSzdBm7PQ=";

    bst::snapshot_reader reader;
    bst::openSnapshot(reader);
    uint64_t expected = 130000;
    uint64_t amount = bst::getP2PKHAmount(reader, claim, signature);
    if (amount != expected)
    {
        cout << "test_dust_pruning--- 1" << endl;
        cout << "expected: " << expected << endl;
        cout << "result  : " << amount << endl;
    }
    expected = 0;
    amount = bst::getP2PKHAmount(reader, claim, signature2);
    if (amount != expected)
    {
        cout << "test_dust_pruning--- 2" << endl;
        cout << "expected: " << expected << endl;
        cout << "result  : " << amount << endl;
    }
}

// only tests libbitcoin code, ignore
void test_validate_multisig()
{
    string transaction_string = "0100000001a9dd2ae0a5d513a336a2c61db3472e260443eb79ffbd07e154829574c1fa2f3901000000fc00"
        "473044022062b5798436e9524c267f5c03c0601743db0cd3e57722c87a48a51d3af4089ccc02200f00f9e244e1fc6fa8141a4e90fa"
        "43b0423d5eda7a1d6d9eb6f6a375337ceda30147304402204ae544e90a9cdf70db7a571cc44a7dcdc0c9f5cbffea6172d7d8ef625d"
        "ea0758022074c3fa6437c60a762dd49075d80855eec78ea27fafff5e78fb70e07985c9f833014c69522102f91ca5628d8a77fbf8e1"
        "2fd098fdd871bdcb61c84cc3abf111a747b26ff6a2cb2103b708d33d5452ce8232fe096220ad2aaea4aa68ce0f0869e6321e93c88c"
        "f5ce082103917f030d239db795047bb5eb66713838221134e103eee2da5619c0cd938e6f6953aeffffffff0170c9fa020000000019"
        "76a914f2f5bbdea2763591bb5c7552df7d6fe46204bc7588ac00000000";
    bc::data_chunk transaction_chunk;
    bc::decode_base16(transaction_chunk, transaction_string);
    bc::transaction_type transaction;
    bc::satoshi_load(transaction_chunk.begin(), transaction_chunk.end(), transaction);

    string output_string = "a91489a16fbc4929fc7c83ada40641411c09fe4b76d887";
    bc::data_chunk output_chunk;
    bc::decode_base16(output_chunk, output_string);
    bc::script_type output_script = bc::parse_script(output_chunk);

    bc::script_type input_script = transaction.inputs[0].script;
    bool result = output_script.run(input_script, transaction, 0);

    cout << bc::pretty(transaction) << endl;
    cout << bc::pretty(output_script) << endl;
    cout << "result " << result << endl;
}

// not a test, just making a pretty base58 dummy address
void make_dummy_address()
{
    //              1AsyXxD2CLwZtQEm7SuKcfEVpHuQVDQ174
    string dummy = "1BitcoinSnapshotDummyAddress111111";
    bc::data_chunk chunk = bc::decode_base58(dummy);
    bc::short_hash sh = bc::short_hash();
    copy(chunk.begin() + 1, chunk.begin() + 22, sh.begin());
    bc::payment_address address(0, sh);
    string recoveredAddress = address.encoded();
    string hexString = bc::encode_base16(sh);
    cout << recoveredAddress << endl;

    cout << hexString << endl;
}

void test_claim_bitfield()
{
    bst::snapshot_preparer preparer;
    preparer.debug = false;
    bst::prepareForUTXOs(preparer);
    string pk1 = "1345FBB2B00E115C98C1D6E975C99B5431DE9CDE";
    string pk2 = "2345FBB2B00E115C98C1D6E975C99B5431DE9CDE";
    string pk3 = "3345FBB2B00E115C98C1D6E975C99B5431DE9CDE";
    string pk4 = "4345FBB2B00E115C98C1D6E975C99B5431DE9CDE";
    string pk5 = "5345FBB2B00E115C98C1D6E975C99B5431DE9CDE";
    string pk6 = "6345FBB2B00E115C98C1D6E975C99B5431DE9CDE";
    string pk7 = "7345FBB2B00E115C98C1D6E975C99B5431DE9CDE";
    string pk8 = "8345FBB2B00E115C98C1D6E975C99B5431DE9CDE";
    string pk9 = "9345FBB2B00E115C98C1D6E975C99B5431DE9CDE";
    string pks[9] = { pk1, pk2, pk3, pk4, pk5, pk6, pk7, pk8, pk9 };
    for (int i = 0; i < 9; i++) {
        string transaction = "76A914" + pks[i] + "88AC";
        vector<uint8_t> vector;
        bst::decodeVector(transaction, vector);
        bst::writeUTXO(preparer, vector, (uint64_t) i * 100);
    }
    string pk10 = "69a16fbc4929fc7c83ada40641411c09fe4b76d8";
    string pk11 = "79a16fbc4929fc7c83ada40641411c09fe4b76d8";
    string pkss[2] = { pk10, pk11 };
    for (int i = 0; i < 2; i++) {
        string transaction = "a914" + pkss[i] + "87";
        vector<uint8_t> vector;
        bst::decodeVector(transaction, vector);
        bst::writeUTXO(preparer, vector, (uint64_t) 10000 * i);
    }
    vector<uint8_t> block_hash = vector<uint8_t>(32);
    bst::writeJustSqlite(preparer);
    bst::writeSnapshotFromSqlite(block_hash, 0);


    bst::snapshot_reader reader;
    bst::openSnapshot(reader);

    for (int i = 0; i < 9; i++) {
        vector<uint8_t> vector;
        bst::decodeVector(pks[i], vector);
        if (getP2PKHClaimed(reader, vector)) {
            cout << "after taking snapshot, claim " << i << " is set" << endl;
        }
    }
    for (int i = 0; i < 2; i++) {
        vector<uint8_t> vector;
        bst::decodeVector(pkss[i], vector);
        if (bst::getP2SHClaimed(reader, vector)) {
            cout << "after taking snapshot, claim 1" << i << " is set" << endl;
        }
        if (! setP2SHClaimed(reader, vector)) {
            cout << "error setting p2sh claim" << endl;
        }
        if (! getP2SHClaimed(reader, vector)) {
            cout << "after setting, claim 10 is not set" << endl;
        }
    }

    vector<uint8_t> vector, vector2;
    for (int i = 0; i < 9; i++) {
        vector.clear();
        bst::decodeVector(pks[i], vector);
        if (! bst::setP2PKHClaimed(reader, vector)) {
            cout << "error setting p2pkh claim " << i << endl;
        }
        for (int j = 0; j < 9; j++) {
            vector2.clear();
            bst::decodeVector(pks[j], vector2);
            if (j == i) {
                if (! bst::getP2PKHClaimed(reader, vector2)) {
                   cout << "after setting, claim " << j << " is not set" << endl;
                }
            } else {
                if (bst::getP2PKHClaimed(reader, vector2)) {
                    cout << "after setting " << i << " claim " << j << " is set" << endl;
                }
            }
        }
        bst::resetClaims(reader.header);
    }

    // cleanup
    remove("temp.sqlite");
}

void test_all()
{
    test_signing_check();
    test_recover_signature();
    test_store_and_claim();
    test_write_sql_and_snapshot_separately();
    test_claim_bitfield();
    test_dust_pruning();
}

void temp_make_address()
{
    // disagree amounts
    /*
    string adr1 = "3B4DF4363CAA9E3BD9DA58020D3080BE8230A4AE";
    string adr2 = "40FA4C9FF96DF3FA85B605A75FE9233589F6D0A3";
    string adr3 = "62E907B15CBF27D5425399EBF6F0FB50EBB88F18";
    string adr4 = "946DA2BD625B8EA667A8069EA21E45051ABF9DE3";
    string adr5 = "ACD6BBBABA2EF8C2C3A8203222DECBCFE1488D32";
     */

    // bill missed
    /*
    string adr1 = "00322511BD4404BD1EE1A740B88C805F47742C20";
    string adr2 = "0037720AF78B49D338C69D12530C4ADF9E901959";
    string adr3 = "00F6BB0BEA9ADDB8E047C2B1F4D89D73E9D6DE05";
    string adr4 = "01307839686B19A5B640EFE6BCAF387F37F0810F";
    string adr5 = "013D7DA172F349867EF4745B9CA73142E35EBBEA";
     */
    string adr1 = "596cc609a9ce1c533a2a224904d2862433f6431a";
    string adr2 = "3534c25a8d3396f3e62a98b6f13f7827db8a026e";
    string adr3 = "b1397ddfcfd4a4c41b0837ffdbcb44d97d15f37e";
    string adr4 = "3b620a56fd3fea79d0f98a49f2c74dd17d65b9bf";
    string adr5 = "5d6f494ed517995b36b9aab9c3e51648b9096388";
    //this doesn't exist
    //string adr6 = "3574A40C27E1B8679E6841B15E235BC942835469";
    string adr6 = "00322511BD4404BD1EE1A740B88C805F47742C20";
    string adrs[6] = { adr1, adr2, adr3, adr4, adr5, adr6 };

    for (int i = 0; i < 6; i++) {
        bc::data_chunk chunk;
        bc::decode_base16(chunk, adrs[i]);
        bc::short_hash shortHash;
        copy(chunk.begin(), chunk.end(), shortHash.begin());
        bc::payment_address payment_address(5, shortHash);
        cout << payment_address.encoded() << endl;
    }

}

int main() {
    test_all();
    //temp_make_address();

    return 0;
}
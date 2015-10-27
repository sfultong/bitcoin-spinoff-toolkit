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
    bst::writeSnapshot(preparer, block_hash);
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
    bst::writeSnapshot(preparer, block_hash);
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
    bst::writeSnapshot(preparer, block_hash);
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

void test_all()
{
    test_signing_check();
    test_recover_signature();
    test_store_and_claim();
}

int main() {
    //test_validate_multisig();
    //test_store_p2pkhs_and_p2sh();
    //test_store_and_claim();
    test_all();

    return 0;
}
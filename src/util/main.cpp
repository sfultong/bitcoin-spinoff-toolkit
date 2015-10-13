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

    string result = bst::getVerificationMessage(testEncodedAddress, messageToSign, signatureString);
    cout << result << endl;
}

void test_recover_signature()
{
    string testEncodedAddress = "15BWWGJRtB8Z9NXmMAp94whujUK6SrmRwT";
    string messageToSign = "hey there";
    string signatureString = "HxXI251uSorWtrqkZejCljYlU+6s861evqN6u3IyYJVSaqYooYzvuSCf6TA0B+wJDOkqljz0fQgkvKjJHiBJgRg=";
    cout << testEncodedAddress << endl;

    vector<uint8_t> paymentVector = vector<uint8_t>(20);
    bool result = bst::recover_address(messageToSign, signatureString, paymentVector);
    bc::short_hash sh;
    copy(paymentVector.begin(), paymentVector.end(), sh.begin());
    bc::payment_address address(0, sh);
    cout << result << " " << address.encoded() << endl;
}

void test_string_encode_decode()
{
    string vectorString = "01AF0F10";
    vector<uint8_t> testVec;
    bst::decodeVector(vectorString, testVec);
    stringstream ss;
    bst::prettyPrintVector(testVec, ss);
    string s = ss.str();
    cout << vectorString << endl << s << endl;
}

void test_string_encode_decode2()
{
    string vectorString = "992fa68a35e9706f5ce12036803df00ff3003dc6";
    vector<uint8_t> testVec;
    bst::decodeVector(vectorString, testVec);
    stringstream ss;
    bst::prettyPrintVector(testVec, ss);
    string s = ss.str();
    cout << vectorString << endl << s << endl;
}

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

void test_store_and_claim()
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
    string claim = "I claim funds.";
    string signature = "Hxc0sSkslD2mFE3HtHzIDRqSutQBiAQ+TxrsgVPeL3jWbXtcusuD77MTX7Tc/hJsQtVrbZsf9xpSDs+6Khx7nNk=";
    string signature2 = "H3ys4y9vnG2cvneZMo33Vvv1kQTKr2iCcBZZe78OFl8VaPbXYNwLVTtTh5K7Qu4MpdOQiVo+6SHq6pPSzdBm7PQ=";

    bst::snapshot_reader reader;
    bst::openSnapshot(reader);
    uint64_t amount = bst::getP2PKHAmount(reader, claim, signature);
    cout << "found amount " << amount << endl;
    amount = bst::getP2PKHAmount(reader, claim, signature2);
    cout << "found amount " << amount << endl;
}

int main() {
    test_store_and_claim();

    return 0;
}
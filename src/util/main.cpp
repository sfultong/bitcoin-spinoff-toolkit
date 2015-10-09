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
    bst::writeSnapshot(preparer);
}

int main() {
    test_store_p2pkhs();

    return 0;
}
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

int new_keypair()
{
    /*
    bc::ec_point point;
    bc::ec_secret secret;
     bc::elliptic_curve_key ec;
    ec.new_key_pair();
    private_data raw_private_key = ec.private_key();
    std::cout << std::string(raw_private_key.begin(), raw_private_key.end());
     */
    return 0;
}

int main() {
    string testEncodedAddress = "15BWWGJRtB8Z9NXmMAp94whujUK6SrmRwT";
    string messageToSign = "hey there";
    string signatureString = "HxXI251uSorWtrqkZejCljYlU+6s861evqN6u3IyYJVSaqYooYzvuSCf6TA0B+wJDOkqljz0fQgkvKjJHiBJgRg=";

    string result = bst::getVerificationMessage(testEncodedAddress, messageToSign, signatureString);
    cout << result << endl;

    bst::testSqlite(cout);

    return 0;
}
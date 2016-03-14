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
#ifndef SPINOFF_TOOLKIT_MISC_H
#define SPINOFF_TOOLKIT_MISC_H

#include <fstream>
#include "common.h"

using namespace std;

namespace bst {

    string getVerificationMessage(string address, string message, string signature);
    bool recover_address(const string &message, const string &signature, vector <uint8_t> &paymentVector);

    // remove these two
    void prettyPrintVector(const vector<uint8_t>& vector, stringstream& ss);
    bool decodeVector(const string& vectorString, vector<uint8_t>& vector);
}

#endif
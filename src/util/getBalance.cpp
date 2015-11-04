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
#include "bitcoin/bst/claim.h"

using namespace std;

int main(int argv, char** argc) {
    bst::snapshot_reader snapshot_reader;
    if (! bst::openSnapshot(snapshot_reader)) {
        cout << "Could not open snapshot." << endl;
        return -1;
    }

    if (argv != 2) {
        cout << "Usage: get_balance <address>" << endl;
        return -1;
    }

    stringstream ss;
    ss << argc[1];
    bc::payment_address payment_address;
    if (! payment_address.set_encoded(ss.str())) {
        cout << "bad address" << endl;
        return -1;
    }
    vector<uint8_t> addressVec = vector<uint8_t>(payment_address.hash().begin(), payment_address.hash().end());

    uint64_t amount = bst::getP2PKHBalance(snapshot_reader, addressVec);
    if (amount != 0)
    {
        cout << "found p2pkh amount " << amount << endl;
        return 0;
    }

    amount = bst::getP2SHBalance(snapshot_reader, addressVec);
    if (amount != 0)
    {
        cout << "found p2sh amount " << amount << endl;
        return 0;
    }

    cout << "could not find address in snapshot" << endl;
   return 0;
}

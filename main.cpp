/**
 * Copyright (C) 2015 Bitcoin Spinoff Toolkit developers

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <iostream>
#include <bitcoin/bitcoin.hpp>
#include <stdint-gcc.h>

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
    bc::payment_address address;
    if (address.set_encoded(testEncodedAddress)) {
        bc::message_signature decodedSignature;
        bc::data_chunk chunk;
        if (bc::decode_base64(chunk, signatureString)) {
            copy(chunk.begin(), chunk.end(), decodedSignature.begin());
            vector<uint8_t> messageBytes(messageToSign.begin(),messageToSign.end());
            bc::array_slice<uint8_t> slice(messageBytes);
            if (bc::verify_message(slice, address, decodedSignature)) {
                cout << "wow, we verified this" << endl;
            } else {
                cout << "signature doesn't match" << endl;
            }
        } else {
            cout << "signature invalid encoding" << endl;
        }
    } else {
        cout << "Invalid Address" << endl;
    }

    return 0;
}
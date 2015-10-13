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

#include <bitcoin/bitcoin/define.hpp>
#include <bitcoin/bitcoin/math/ec_keys.hpp>
#include <bitcoin/bitcoin/math/secp256k1_initializer.hpp>
#include <bitcoin/bitcoin/wallet/message.hpp>
#include <bitcoin/bitcoin/formats/base64.hpp>
#include "bitcoin/bst/generate.h"

using namespace std;

namespace bst {

    bool recover_address(const string& message, const string& signature, vector<uint8_t>& paymentVector) {
        // convert signature string from base64
        bc::message_signature decodedSignature = bc::message_signature();
        bc::data_chunk chunk;
        if (!bc::decode_base64(chunk, signature)) return false;

        // copy
        copy(chunk.begin(), chunk.end(), decodedSignature.begin());
        std::vector<uint8_t> messageBytes(message.begin(), message.end());
        bc::array_slice <uint8_t> slice = bc::array_slice<uint8_t>(messageBytes);

        bc::hash_digest message_hash = hash_message(slice);

        bool compressed = false;
        int magic = decodedSignature[0] - 27;
        if (magic < 0 || 8 <= magic) {
            return false;
        }
        if (4 <= magic) {
            compressed = true;
            magic -= 4;
        }

        bc::compact_signature cs = bc::compact_signature();
        std::copy(decodedSignature.begin() + 1, decodedSignature.end(), cs.signature.begin());
        cs.recid = magic;
        bc::ec_point pubkey = bc::recover_compact(cs, message_hash, compressed);
        auto pkh = bc::bitcoin_short_hash(pubkey);
        copy(pkh.begin(), pkh.end(), paymentVector.begin());
        return true;
    }
}
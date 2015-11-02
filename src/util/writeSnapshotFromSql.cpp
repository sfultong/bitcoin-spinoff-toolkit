#include <iostream>
#include <bitcoin/bitcoin.hpp>
#include "bitcoin/bst/generate.h"

using namespace std;

int main() {

    vector<uint8_t> block_hash = vector<uint8_t>(32);
    bst::writeSnapshotFromSqlite(block_hash);

    return 0;

}

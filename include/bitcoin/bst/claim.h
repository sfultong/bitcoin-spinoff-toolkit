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
#ifndef SPINOFF_TOOLKIT_CLAIM_H
#define SPINOFF_TOOLKIT_CLAIM_H

#include <fstream>
#include "common.h"

using namespace std;

namespace bst {

    struct snapshot_reader
    {
        ifstream* snapshot;
        snapshot_header header;

        snapshot_reader() {}
        snapshot_reader(const snapshot_reader& other) {
            snapshot = other.snapshot;
            header = other.header;
        }
    };

    class SnapshotEntryCollection {
    public:
        SnapshotEntryCollection(const snapshot_reader& reader_, int64_t amount_, uint64_t offset_, uint64_t claimed_offset_) {
            reader = reader_;
            amount = amount_;
            offset = offset_;
            claimed_offset = claimed_offset_;
        }
        SnapshotEntryCollection(const SnapshotEntryCollection& other) {
            reader = other.reader;
            amount = other.amount;
            offset = other.offset;
            claimed_offset = other.claimed_offset;
        }
        SnapshotEntryCollection& operator=(const SnapshotEntryCollection& other) {
            reader = other.reader;
            amount = other.amount;
            offset = other.offset;
            claimed_offset = other.claimed_offset;
            return *this;
        }

        void getEntry(int64_t index, snapshot_entry& entry) const;
        bool getEntry(const uint256_t& hash, snapshot_entry& entry);
        bool getEntry(const string& claim, const string& signature, snapshot_entry& entry);
        bool getEntry(const string& claim, const uint256_t signature, snapshot_entry& entry);
        void setClaimed(int64_t index);
        snapshot_reader reader;
        int64_t amount;
        uint64_t offset;
        uint64_t claimed_offset;

        class iterator {
        public:
            typedef iterator self_type;
            typedef snapshot_entry value_type;
            typedef snapshot_entry& reference;
            typedef snapshot_entry* pointer;
            typedef int64_t difference_type;
            typedef random_access_iterator_tag iterator_category;
            iterator() : collection(0), index(0) {} // broken, dunno why I should implement this
            iterator(const SnapshotEntryCollection* collection_) : index(0) { collection = collection_; }
            iterator(const SnapshotEntryCollection* collection_, int64_t index_) { collection = collection_; index = index_; }
            self_type operator++() { self_type i = *this; index++; return i; }
            self_type operator++(int junk) { index++; return *this; }
            reference operator*() { collection->getEntry(index, current_entry); return current_entry; }
            pointer operator->() { collection->getEntry(index, current_entry); return &current_entry; }
            bool operator==(const self_type& rhs) { return index == rhs.index; }
            bool operator!=(const self_type& rhs) { return index != rhs.index; }
        //protected:
            const SnapshotEntryCollection* collection;
            snapshot_entry current_entry;
            int64_t index;
        };

        class const_iterator {
        public:
            typedef const_iterator self_type;
            typedef snapshot_entry value_type;
            typedef const snapshot_entry& reference;
            typedef const snapshot_entry* pointer;
            typedef int64_t difference_type;
            typedef input_iterator_tag iterator_category;
            const_iterator(const SnapshotEntryCollection* collection_) : index(0) { collection = collection_; }
            const_iterator(const SnapshotEntryCollection* collection_, int64_t index_) { collection = collection_; index = index_; }
            const_iterator(const iterator& other) {collection = other.collection; index = other.index; }
            self_type operator++() { self_type i = *this; index++; return i; }
            self_type operator++(int junk) { index++; return *this; }
            reference operator*() { collection->getEntry(index, current_entry); return current_entry; }
            pointer operator->() { collection->getEntry(index, current_entry); return &current_entry; }
            bool operator==(const self_type& rhs) { return index == rhs.index; }
            bool operator!=(const self_type& rhs) { return index != rhs.index; }
        private:
            const SnapshotEntryCollection* collection;
            snapshot_entry current_entry;
            int64_t index;
        };
        iterator begin() { return iterator(this); }
        iterator end() { return iterator(this, amount);}
        const_iterator begin() const { return const_iterator(this); }
        const_iterator end() const { return const_iterator(this, amount); }
    };

    bool openSnapshot(ifstream& stream, snapshot_reader& reader);

    SnapshotEntryCollection getP2PKHCollection(const snapshot_reader& reader);
    SnapshotEntryCollection getP2SHCollection(const snapshot_reader& reader);

    void printSnapshot();

    uint64_t getP2PKHAmount(SnapshotEntryCollection& collection, const string& claim, const string& signature);
    uint64_t getP2SHAmount(SnapshotEntryCollection& collection, const string& transaction, const string& address, const uint32_t input_index);
}

#endif

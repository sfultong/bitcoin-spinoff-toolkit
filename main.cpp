#include <iostream>
#include <bitcoin/bitcoin.hpp>

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
    string testEncodedAddress = "1KvYT82JhJLhZTnVsp3MwPnFJLkc73Tn27";
    bc::payment_address address;
    if (address.set_encoded(testEncodedAddress)) {
        cout << "Nice, it worked" << endl;
        cout << address.encoded() << endl;
    } else {
        cout << "Failure!" << endl;
    }


    return 0;
}
#include <string.h>
#include <iostream>
#include <bitcoin/bitcoin.hpp>
#include <boost/format.hpp>
#include <boost/algorithm/string.hpp>
#include "coin_data.h"

#define BIP_NUMBER 44

using namespace bc;
using namespace wallet;
using namespace chain;
using namespace machine;

void build_transaction(const wallet::hd_private& hd_deriver_key, const coin_data& coin) {

    auto derived0 = hd_deriver_key.derive_private(0);
    auto sig = derived0.secret();
    //derived0.

    // ******* part 1 *******

    // Instantiate tx object.
    transaction tx;

    // ******* part 2 *******.

    // Version 
    uint32_t version = 160u;
    tx.set_version(version);

    // Print version in serialised format.
    auto serialised_version = to_little_endian(tx.version());
    std::cout << encode_base16(to_chunk(serialised_version));

    //******* part 3 *******

    // Previous TX hash.
    std::string prev_tx_string_0 = "5209723d5612a46836b3ad1f4ccddd254e24b80cbfb72e002b939a6b33798ded";
    hash_digest prev_tx_hash_0;
    decode_hash(prev_tx_hash_0, prev_tx_string_0);

    // Previous UXTO index.
    uint32_t index0 = 0;
    output_point uxto_tospend_0(prev_tx_hash_0, index0);

    // Build input_0 object.
    input input_0;
    input_0.set_previous_output(uxto_tospend_0);
    input_0.set_sequence(0xffffffff);

    // Additional input objects can be created for additional inputs

    // All input objects can then be added to transaction
    tx.inputs().push_back(input_0);        //first input
    // tx.inputs().push_back(input_1);     //second input
                                           //...nth input

    // Input script will be added later.


    // ******* part 4 *******

    // Destination Address
    auto dest_address_raw = "EKLiqAS8154uEEtRGHZ4PJax64o4nC5Jgw";
    payment_address dest_address1(dest_address_raw);

    auto dest_address_raw2 = "EarTiDEmacVgSfFkukqUFBmseeHBCLdrs8";
    payment_address dest_address2(dest_address_raw2);

    // Create Output output script/scriptPubKey from template:
    operation::list output_script_0=script::to_pay_key_hash_pattern(dest_address1.hash());
    operation::list output_script_1=script::to_pay_key_hash_pattern(dest_address2.hash());

    // Define Output amount
    std::string btc_amount_string_0 = "15";
    uint64_t satoshi_amount_0;
    decode_base10(satoshi_amount_0, btc_amount_string_0, btc_decimal_places); // btc_decimal_places = 8

    std::string btc_amount_string_1 = "184.99965400";
    uint64_t satoshi_amount_1;
    decode_base10(satoshi_amount_1, btc_amount_string_1, btc_decimal_places); // btc_decimal_places = 8

    // Create output_0 object
    output output_0(satoshi_amount_0, output_script_0);
    output output_1(satoshi_amount_1, output_script_1);

    // Above can be repeated for other outputs

    // Add outputs to TX
    tx.outputs().push_back(output_0);     //first output
    tx.outputs().push_back(output_1);     //first output
    // tx.outputs().push_back(output_1);   //second output
    // tx.outputs().push_back(output_n);   //...nth output

    // ******* part 5 *******

    // We rebuild our P2PKH script manually:
    operation::list my_own_p2pkh;
    my_own_p2pkh.push_back(operation(opcode::dup));
    my_own_p2pkh.push_back(operation(opcode::hash160));
    operation op_pubkey = operation(to_chunk(dest_address1.hash()));
    my_own_p2pkh.push_back(op_pubkey); //includes hash length prefix
    my_own_p2pkh.push_back(operation(opcode::equalverify));
    my_own_p2pkh.push_back(operation(opcode::checksig));

    // The two operation lists are equivalent
    std::cout << (my_own_p2pkh == output_script_0) << std::endl;

    // ******* part 6 *******

    // Signer: Secret > Pubkey > Address
    //sig.
    ec_private my_private0(sig, ec_private::to_version(
                coin.pubkey_address, coin.secret_key), true);
    ec_compressed pubkey0= my_private0.to_public().point();
    payment_address my_address0 = my_private0.to_payment_address();

    std::cout << "PAYMENT ADDRESS: " << my_address0 << std::endl;

    // Signature
    endorsement sig_0;
    script prev_script_0 = script::to_pay_key_hash_pattern(my_address0.hash());
    uint8_t input0_index(0u);
    script::create_endorsement(sig_0, sig, prev_script_0, tx,
        input0_index, 0x01);

    // Create input script
    operation::list sig_script_0;
    sig_script_0.push_back(operation(sig_0));
    sig_script_0.push_back(operation(to_chunk(pubkey0)));
    script my_input_script_0(sig_script_0);

    std::cout << "INPUT SCRIPT: " << encode_base16(my_input_script_0.to_data(false)) << std::endl;

    // Add input script to first input in transaction
    //tx.inputs()[0].set_script(my_input_script_0);
    chain::witness w(my_input_script_0.to_data(true), true);
    std::cout << "WITNESS: " << w.to_string() << std::endl;
    tx.inputs()[0].set_witness(w);

    // Print serialised transaction
    std::cout << encode_base16(tx.to_data()) << std::endl;

}


int main(int argc, char* argv[]) {
    if (argc < 2) {
        std:cerr << "Syntax: wallet-get <coin> <net>" << std::endl;
        return -1;
    }
    const char* coin_name = argv[1];
    const char* net = argv[2];

    auto& coin = coin_data::get_coin_data(coin_name, net);

    const uint64_t custom_key_prefixes = wallet::hd_private::to_prefixes(
        coin.get_secret_key_prefix(),
        coin.get_public_key_prefix());

    wallet::word_list mnemonic_words;
    std::string input_words;

    std::cout << "Enter mnemonic (empty to autogenerate): ";
    std::getline(cin, input_words);
    if (input_words == "") {
        data_chunk my_entropy(32);
        pseudo_random_fill(my_entropy);
        mnemonic_words = wallet::create_mnemonic(my_entropy);
        std::cout << boost::format("// %s") % bc::join(mnemonic_words) << std::endl;
    } else {
        boost::split(mnemonic_words, input_words, boost::is_space());
    }

    auto hd_seed = wallet::decode_mnemonic(mnemonic_words);
    data_chunk seed_chunk(to_chunk(hd_seed));

    std::cout << "seed: " << encode_base16(hd_seed) << std::endl;

    wallet::hd_private m(seed_chunk, custom_key_prefixes);
    std::cout << "BIP32 Root Key: " << m << std::endl;
    auto m_purpose = m.derive_private(wallet::hd_first_hardened_key + BIP_NUMBER);
    auto m_coin = m_purpose.derive_private(coin.bip44_id);
    auto m_account = m_coin.derive_private(wallet::hd_first_hardened_key + 0);
    auto m_ext = m_account.derive_private(0);




    build_transaction(m_ext, coin);

    return 0;

}

// Copyright (c) 2018 Rodimiro Cerrato
// Distributed under the Apache License Version 2.0

#include <iostream>
#include <unordered_map>
#include <string>
#include <bitcoin/bitcoin.hpp>
#include <boost/format.hpp>
#include "coin_data.h"

using namespace bc;


#define COIN 100000000 // 10**8
#define DEFAULT_N_ACCOUNTS 4
#define DEFAULT_TOTAL_WALLET_AMOUNT 2000
#define DEFAULT_N_COINS_PER_ACCOUNT 10


int main(int argc, char* argv[]) {
    if (argc < 3) {
        std:cerr << "Syntax: wallet-get <coin> <net>" << std::endl;
        return -1;
    }
    const char* coin_name = argv[1];
    const char* net = argv[2];
    const auto n_accounts = argc > 3 ? atoi(argv[3]) : DEFAULT_N_ACCOUNTS;
    const auto total_wallet_amount = argc > 4 ? atoi(argv[4]) : DEFAULT_TOTAL_WALLET_AMOUNT;
    const auto n_coins_per_account = argc > 5 ? atoi(argv[5]) : DEFAULT_N_COINS_PER_ACCOUNT;

    auto& coin = coin_data::get_coin_data(coin_name, net);

    //std::cout << "pubkey prefix: " << std::hex << coin_prefixes.get_public_key_prefix() << std::endl;

    const uint64_t custom_key_prefixes = wallet::hd_private::to_prefixes(
        coin.get_secret_key_prefix(),
        coin.get_public_key_prefix());

    data_chunk my_entropy(32);

    for (int i = 0; i < n_accounts; i++) {
        pseudo_random_fill(my_entropy);
        auto mnemonic_words = wallet::create_mnemonic(my_entropy);
        std::cout << boost::format("// %s") % bc::join(mnemonic_words) << std::endl;

        auto hd_seed = wallet::decode_mnemonic(mnemonic_words);
        data_chunk seed_chunk(to_chunk(hd_seed));

        //std::cout << "seed: " << encode_base16(hd_seed) << std::endl;

        wallet::hd_private m(seed_chunk, custom_key_prefixes);
        //std::cout << "BIP32 Root Key: " << m << std::endl;
        auto m_purpose = m.derive_private(wallet::hd_first_hardened_key + 44);
        auto m_coin = m_purpose.derive_private(coin.bip44_id);
        auto m_account = m_coin.derive_private(wallet::hd_first_hardened_key + 0);
        auto m_ext = m_account.derive_private(0);

        /*
        std::cout << std::endl;
        std::cout << "Account extended PrvKey: " << m_account << std::endl;
        std::cout << "Account extended PubKey: " << m_account.to_public() << std::endl;
        std::cout << std::endl;
        std::cout << "BIP32 Extended Private Key: " << m_ext << std::endl;
        std::cout << "BIP32 Extended Public Key:  " << m_ext.to_public() << std::endl;
        std::cout << std::endl;
        */



        for (int i = 0; i < n_coins_per_account; i++) {
            auto mi = m_ext.derive_private(i);
            auto Mi = mi.to_public();

            //std::cout << boost::format("m/%d'/%d") % 0 % i << std::endl;
            
            //std::cout << "Public key: " << encode_base16(Mi.point()) << std::endl;
            
            auto pv_key = wallet::ec_private(
                mi.secret(),
                wallet::ec_private::to_version(
                    coin.pubkey_address, coin.secret_key));

            //std::cout << "Private key: " << pv_key << std::endl;
            
            auto payment_addr = pv_key.to_payment_address();
            //std::cout << "Address: " << payment_addr.encoded() << std::endl;

            auto pubkey_hash = bitcoin_short_hash(mi.point());
            //std::cout << "Public Key HASH: " << encode_base16(pubkey_hash) << std::endl;

            auto amount = (unsigned long)total_wallet_amount / n_coins_per_account;
            std::cout << boost::format("std::make_pair(\"%s\", %u * COIN),") % encode_base16(pubkey_hash) % (amount) << std::endl;

            //std::cout << std::endl;
        }

        std::cout << std::endl;
    }

    return 0;
}


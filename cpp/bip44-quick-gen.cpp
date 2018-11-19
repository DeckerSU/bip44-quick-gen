#include <bitcoin/bitcoin.hpp>
#include <boost/format.hpp>
#include <boost/algorithm/string.hpp>
#include "coin_data.h"

#define BIP_NUMBER 44

using namespace bc;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Syntax: wallet-get <coin> <net>" << std::endl;
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
    std::getline(std::cin, input_words);
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
    std::cout << "SECRET SIZE: " << m.secret().size() << std::endl;
    auto m_purpose = m.derive_private(wallet::hd_first_hardened_key + BIP_NUMBER);
    auto m_coin = m_purpose.derive_private(coin.bip44_id);
    auto m_account = m_coin.derive_private(wallet::hd_first_hardened_key + 0);
    auto m_ext = m_account.derive_private(0);

    std::cout << std::endl;
    std::cout << "Account extended PrvKey: " << m_account << std::endl;
    std::cout << "Account extended PubKey: " << m_account.to_public() << std::endl;
    std::cout << std::endl;
    std::cout << "BIP32 Extended Private Key: " << m_ext << std::endl;
    std::cout << "BIP32 Extended Public Key:  " << m_ext.to_public() << std::endl;
    std::cout << std::endl;

    for (int i = 0; i < 1000; i++) {
        auto mi = m_ext.derive_private(i);
        auto Mi = mi.to_public();

        auto pv_key = wallet::ec_private(
            mi.secret(),
            wallet::ec_private::to_version(
                coin.pubkey_address, coin.secret_key));

        auto payment_addr = pv_key.to_payment_address();

        //std::cout << boost::format("m/%d'/%d'/%d'/%d/%d: %s %s") % BIP_NUMBER % (coin.bip44_id - wallet::hd_first_hardened_key) % 0 % 0 % i % payment_addr.encoded() % pv_key.encoded() << std::endl;
        std::cout << boost::format("./komodo-cli importprivkey \"%s\" \"\" false # m/%d'/%d'/%d'/%d/%d: %s") % pv_key.encoded() % BIP_NUMBER % (coin.bip44_id - wallet::hd_first_hardened_key) % 0 % 0 % i % payment_addr.encoded() << std::endl;
    }

    std::cout << std::endl;

    return 0;
}

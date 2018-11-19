#ifndef __COIN_DATA_H__
#define __COIN_DATA_H__

#include <string>

struct coin_data {
    const uint8_t pubkey_address;
    const uint8_t script_address;
    const uint8_t pubkey_address_256;
    const uint8_t script_address_256;
    const uint8_t secret_key;
    const uint8_t ext_public_key[4];
    const uint8_t ext_secret_key[4];
    //const uint8_t stealth_address;
    //const uint8_t ext_key_hash;
    //const uint8_t ext_acc_hash;
    const int bip44_id;

    uint32_t get_public_key_prefix() const;
    uint32_t get_secret_key_prefix() const;
    static const coin_data& get_coin_data(const std::string&, const std::string&);

private:
    static uint32_t to_prefix(const uint8_t bytes[]);
};

#endif

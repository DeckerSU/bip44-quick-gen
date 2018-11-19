#include <map>
#include "coin_data.h"    

typedef std::pair<std::string, std::string> coinnet_t;

static std::map<coinnet_t, coin_data> coin_data_map {
    {{"kmd", "mainnet"}, {
        .pubkey_address = 60, // R
        .script_address = 85, // TODO: define
        .pubkey_address_256 = 0x39, // TODO: define
        .script_address_256 = 0x3d, // TODO: define
        .secret_key = 188, 
        .ext_public_key = {0x04, 0x88, 0xb2, 0x1e}, // xpub
        .ext_secret_key = {0x04, 0x88, 0xad, 0xe4}, // xprv
        .bip44_id = (1 << 31) + 0x8d // 141'
    }}
};

uint32_t coin_data::get_public_key_prefix() const {
    return to_prefix(ext_public_key);
}
uint32_t coin_data::get_secret_key_prefix() const {
    return to_prefix(ext_secret_key);
}
const coin_data& coin_data::get_coin_data(const std::string& coin, const std::string& net) {
    return coin_data_map.at(coinnet_t(coin, net));
}

uint32_t coin_data::to_prefix(const uint8_t bytes[]) {
    return bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3];
}

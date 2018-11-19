#include <bitcoin/bitcoin.hpp>
#include <string.h>
#include <iostream>

using namespace bc;
using namespace wallet;
using namespace chain;
using namespace machine;


void sign_sighash_all() {
    // SETUP (Not shown in chapter documentation).
    // Private key, public keys.
    auto my_secret0 = base16_literal(
        "3eec08386d08321cd7143859e9bf4d6f65a71d24f37536d76b4224fdea48009f");
    auto my_secret1 = base16_literal(
        "86faa240ae2b0f28b125a42961bd3adf9d5f5dc6a1deaa5feda04e7be8c872f6");
    auto my_secret2 = base16_literal(
        "b7423c94ab99d3295c1af7e7bbea47c75d298f7190ca2077b53bae61299b70a5");
    auto my_secret3 = base16_literal(
        "d977e2ce0f744dc3432cde9813a99360a3f79f7c8035ef82310d54c57332b2cc");
    ec_private my_private0(my_secret0, ec_private::testnet, true); //compressed
    ec_private my_private1(my_secret1, ec_private::testnet, true); //compressed
    ec_private my_private2(my_secret2, ec_private::testnet, true); //compressed
    ec_private my_private3(my_secret3, ec_private::testnet, true); //compressed
    payment_address my_address0 = my_private0.to_payment_address();
    payment_address my_address1 = my_private1.to_payment_address();
    payment_address my_address2 = my_private2.to_payment_address();
    payment_address my_address3 = my_private3.to_payment_address();
    ec_compressed pubkey0 = my_private0.to_public().point();
    ec_compressed pubkey1 = my_private1.to_public().point();

    // Version.
    uint32_t version = 1u;
    transaction tx;
    tx.set_version(version);

    // Build input 0.
    std::string prev_tx_string_0 =
        "7ea970031b28fcc1cef517dfa7d812cb61c409aec37a0463e951a05700d61b73";
    hash_digest prev_tx_hash_0;
    decode_hash(prev_tx_hash_0,prev_tx_string_0);
    // Prev uxto index.
    uint32_t index0 = 0;
    output_point uxto_tospend_0(prev_tx_hash_0, index0);
    // Input object.
    input input_0;
    input_0.set_previous_output(uxto_tospend_0);
    input_0.set_sequence(max_input_sequence);
    // Build input 1.
    std::string prev_tx_string_1 =

        "32d070ed7d387b9db02bf35f3ba1c0ee61837c2226fd5cbf0c913525a9be869d";
    hash_digest prev_tx_hash_1;
    decode_hash(prev_tx_hash_1,prev_tx_string_1);
    // Prev uxto index.
    uint32_t index1 = 0;
    output_point uxto_tospend_1(prev_tx_hash_1, index1);
    // Input object.
    input input_1;
    input_1.set_previous_output(uxto_tospend_1);
    input_1.set_sequence(max_input_sequence);

    // Build output 0.
    operation::list locking_script_0 =
        script::to_pay_key_hash_pattern(my_address2.hash());
    std::string btc_amount_string_0 = "1";
    uint64_t satoshi_amount_0;
    decode_base10(satoshi_amount_0, btc_amount_string_0, btc_decimal_places);
    output output_0(satoshi_amount_0, locking_script_0);
    // Build output 1.
    operation::list locking_script_1 =
        script::to_pay_key_hash_pattern(my_address3.hash());
    std::string btc_amount_string_1 = "0.945";
    uint64_t satoshi_amount_1;
    decode_base10(satoshi_amount_1, btc_amount_string_1, btc_decimal_places);
    output output_1(satoshi_amount_1, locking_script_1);
    // Build locktime.


    //****************************************//
    // SIGHASH ALL chapter example begins here.

    // Not shown:
    // Construction of inputs and outputs.

    // Finalise TX - can't be modified later.
    tx.inputs().push_back(input_0);   //first input
    tx.inputs().push_back(input_1);   //second input
                                      //...nth input
    tx.outputs().push_back(output_0); //first output
    tx.outputs().push_back(output_1); //second output
                                      //...nth output

    // Construct previous output script of input_0 & input_1.
    script prevout_script0 = script::to_pay_key_hash_pattern(my_address0.hash());
    script prevout_script1 = script::to_pay_key_hash_pattern(my_address1.hash());

    // TX signature for input_0.
    endorsement sig_0;
    uint8_t input0_index(0u);
    script::create_endorsement(sig_0, my_secret0, prevout_script0, tx,
        input0_index, sighash_algorithm::all);

    // TX signature for input_1.
    endorsement sig_1;
    uint8_t input1_index(1u);
    script::create_endorsement(sig_1, my_secret1, prevout_script1, tx,
        input1_index, sighash_algorithm::all);

    // Construct input script_0.
    operation::list sig_script_0;
    sig_script_0.push_back(operation(sig_0));
    sig_script_0.push_back(operation(to_chunk(pubkey0)));
    script input_script0(sig_script_0);

    // Construct input script_1.
    operation::list sig_script_1;
    sig_script_1.push_back(operation(sig_1));
    sig_script_1.push_back(operation(to_chunk(pubkey1)));
    script input_script1(sig_script_1);

    // Add unlockingscript to TX.
    tx.inputs()[input0_index].set_script(input_script0);
    tx.inputs()[input1_index].set_script(input_script1);

    // ALL: We cannot modify TX after signing.

    witness empty_witness;      // Only verified in a p2w tx.
    uint64_t prevout_amount(1); // Only verified in a p2w endorsement.

    // Verify input script (and endorsement) for input 0.
    auto ec_input0 = script::verify(tx, input0_index,rule_fork::all_rules,
          input_script0, empty_witness, prevout_script0,
          prevout_amount);
    // Success.
    std::cout << ec_input0.message() << std::endl;

    // Verify input script (and endorsement) for input 1.
    auto ec_input1 = script::verify(tx, input1_index,rule_fork::all_rules,
          input_script1, empty_witness, prevout_script1,
          prevout_amount);
    // Success.
    std::cout << ec_input1.message() << std::endl;

}

void sign_sighash_none() {
    // SETUP (IDENTICAL IN ALL EXAMPLES)
    // Private key, public keys.
    auto my_secret0 = base16_literal(
        "3eec08386d08321cd7143859e9bf4d6f65a71d24f37536d76b4224fdea48009f");
    auto my_secret1 = base16_literal(
        "86faa240ae2b0f28b125a42961bd3adf9d5f5dc6a1deaa5feda04e7be8c872f6");
    auto my_secret2 = base16_literal(
        "b7423c94ab99d3295c1af7e7bbea47c75d298f7190ca2077b53bae61299b70a5");
    auto my_secret3 = base16_literal(
        "d977e2ce0f744dc3432cde9813a99360a3f79f7c8035ef82310d54c57332b2cc");
    ec_private my_private0(my_secret0, ec_private::testnet, true); //compressed
    ec_private my_private1(my_secret1, ec_private::testnet, true); //compressed
    ec_private my_private2(my_secret2, ec_private::testnet, true); //compressed
    ec_private my_private3(my_secret3, ec_private::testnet, true); //compressed
    payment_address my_address0 = my_private0.to_payment_address();
    payment_address my_address1 = my_private1.to_payment_address();
    payment_address my_address2 = my_private2.to_payment_address();
    payment_address my_address3 = my_private3.to_payment_address();
    ec_compressed pubkey0 = my_private0.to_public().point();
    ec_compressed pubkey1 = my_private1.to_public().point();

    // Version.
    uint32_t version = 1u;
    transaction tx;
    tx.set_version(version);

    // Build input 0.
    std::string prev_tx_string_0 =
        "e964ed0883933ae8f3f53139efef149b0cedb7895a040cab3b64e792acd11412";
    hash_digest prev_tx_hash_0;
    decode_hash(prev_tx_hash_0,prev_tx_string_0);
    // Prev uxto index.
    uint32_t index0 = 0;
    output_point uxto_tospend_0(prev_tx_hash_0, index0);
    // Input object.
    input input_0;
    input_0.set_previous_output(uxto_tospend_0);
    input_0.set_sequence(max_input_sequence);
    // Build input 1.
    std::string prev_tx_string_1 =
        "0aea180c6a3b0233574e9e51f065cd1996f1db6f8a10c72fc480151be323d956";
    hash_digest prev_tx_hash_1;
    decode_hash(prev_tx_hash_1,prev_tx_string_1);
    // Prev uxto index.
    uint32_t index1 = 0;
    output_point uxto_tospend_1(prev_tx_hash_1, index1);
    // Input object.
    input input_1;
    input_1.set_previous_output(uxto_tospend_1);
    input_1.set_sequence(max_input_sequence);

    // Build output 0.
    operation::list locking_script_0 =
        script::to_pay_key_hash_pattern(my_address2.hash());
    std::string btc_amount_string_0 = "0.2";
    uint64_t satoshi_amount_0;
    decode_base10(satoshi_amount_0, btc_amount_string_0, btc_decimal_places);
    output output_0(satoshi_amount_0, locking_script_0);
    // Build output 1.
    operation::list locking_script_1 =
        script::to_pay_key_hash_pattern(my_address3.hash());
    std::string btc_amount_string_1 = "0.287";
    uint64_t satoshi_amount_1;
    decode_base10(satoshi_amount_1, btc_amount_string_1, btc_decimal_places);
    output output_1(satoshi_amount_1, locking_script_1);
    // Build locktime.


    //****************************************//
    // SIGHASH NONE chapter example begins here.

    // Not shown:
    // Construction of inputs and outputs.

    // We only need to finalise inputs. Outputs can be modified after signing.
    tx.inputs().push_back(input_0);   //first input
    tx.inputs().push_back(input_1);   //second input
                                      //...nth input

    // Construct previous output script of input_0 & input_1
    script prevout_script0 = script::to_pay_key_hash_pattern(my_address0.hash());
    script prevout_script1 = script::to_pay_key_hash_pattern(my_address1.hash());

    // TX signature for input_0.
    endorsement sig_0;
    uint8_t input0_index(0u);
    script::create_endorsement(sig_0, my_secret0, prevout_script0, tx,
        input0_index, sighash_algorithm::none);

    // TX signature for input_1.
    endorsement sig_1;
    uint8_t input1_index(1u);
    script::create_endorsement(sig_1, my_secret1, prevout_script1, tx,
        input1_index, sighash_algorithm::none);

    // Construct input script_0.
    operation::list sig_script_0;
    sig_script_0.push_back(operation(sig_0));
    sig_script_0.push_back(operation(to_chunk(pubkey0)));
    script input_script0(sig_script_0);

    // Construct input script_1.
    operation::list sig_script_1;
    sig_script_1.push_back(operation(sig_1));
    sig_script_1.push_back(operation(to_chunk(pubkey1)));
    script input_script1(sig_script_1);

    // Add unlockingscript to TX.
    tx.inputs()[input0_index].set_script(input_script0);
    tx.inputs()[input1_index].set_script(input_script1);

    // NONE: We can modify all outputs after signing
    tx.outputs().push_back(output_0); //first output
    tx.outputs().push_back(output_1); //second output
                                      //...nth output

    witness empty_witness;      // Only verified in a p2w tx.
    uint64_t prevout_amount(1); // Only verified in a p2w endorsement.

    // Verify input script (and endorsement) for input 0.
    auto ec_input0 = script::verify(tx, input0_index,rule_fork::all_rules,
          input_script0, empty_witness, prevout_script0,
          prevout_amount);

    // Success.
    std::cout << ec_input0.message() << std::endl;

    // Verify input script (and endorsement) for input 1.
    auto ec_input1 = script::verify(tx, input1_index,rule_fork::all_rules,
          input_script1, empty_witness, prevout_script1,
          prevout_amount);

    // Success.
    std::cout << ec_input1.message() << std::endl;

}

void sign_sighash_single() {
    // SETUP (IDENTICAL IN ALL EXAMPLES).
    // Private key, public keys.
    auto my_secret0 = base16_literal(
        "3eec08386d08321cd7143859e9bf4d6f65a71d24f37536d76b4224fdea48009f");
    auto my_secret1 = base16_literal(
        "86faa240ae2b0f28b125a42961bd3adf9d5f5dc6a1deaa5feda04e7be8c872f6");
    auto my_secret2 = base16_literal(
        "b7423c94ab99d3295c1af7e7bbea47c75d298f7190ca2077b53bae61299b70a5");
    auto my_secret3 = base16_literal(
        "d977e2ce0f744dc3432cde9813a99360a3f79f7c8035ef82310d54c57332b2cc");
    ec_private my_private0(my_secret0, ec_private::testnet, true); //compressed
    ec_private my_private1(my_secret1, ec_private::testnet, true); //compressed
    ec_private my_private2(my_secret2, ec_private::testnet, true); //compressed
    ec_private my_private3(my_secret3, ec_private::testnet, true); //compressed
    payment_address my_address0 = my_private0.to_payment_address();
    payment_address my_address1 = my_private1.to_payment_address();
    payment_address my_address2 = my_private2.to_payment_address();
    payment_address my_address3 = my_private3.to_payment_address();
    ec_compressed pubkey0 = my_private0.to_public().point();
    ec_compressed pubkey1 = my_private1.to_public().point();

    // Version.
    uint32_t version = 1u;
    transaction tx;
    tx.set_version(version);

    // Build input 0.
    std::string prev_tx_string_0 =
        "3af74abff61f5a8486da92a8fc5e31dc10b899862bf3468d0505a5c1ca550b52";
    hash_digest prev_tx_hash_0;
    decode_hash(prev_tx_hash_0,prev_tx_string_0);
    // Prev uxto index.
    uint32_t index0 = 0;
    output_point uxto_tospend_0(prev_tx_hash_0, index0);
    // Input object.
    input input_0;
    input_0.set_previous_output(uxto_tospend_0);
    input_0.set_sequence(max_input_sequence);
    // Build input 1.
    std::string prev_tx_string_1 =
        "de065530166c16ab1c820b2f4e8e70d8b4259de263d18e47efde41f30ec79970";
    hash_digest prev_tx_hash_1;
    decode_hash(prev_tx_hash_1,prev_tx_string_1);
    // Prevout index.
    uint32_t index1 = 0;
    output_point uxto_tospend_1(prev_tx_hash_1, index1);
    // Input object.
    input input_1;
    input_1.set_previous_output(uxto_tospend_1);
    input_1.set_sequence(max_input_sequence);

    // Build output 0.
    operation::list locking_script_0 =
        script::to_pay_key_hash_pattern(my_address2.hash());
    std::string btc_amount_string_0 = "0.041";
    uint64_t satoshi_amount_0;
    decode_base10(satoshi_amount_0, btc_amount_string_0, btc_decimal_places);
    output output_0(satoshi_amount_0, locking_script_0);
    // Build output 1.
    operation::list locking_script_1
        = script::to_pay_key_hash_pattern(my_address3.hash());
    std::string btc_amount_string_1 = "0.03";
    uint64_t satoshi_amount_1;
    decode_base10(satoshi_amount_1, btc_amount_string_1, btc_decimal_places);
    output output_1(satoshi_amount_1, locking_script_1);
    // Build output 2.
    operation::list locking_script_2
        = script::to_pay_key_hash_pattern(my_address3.hash());
    std::string btc_amount_string_2 = "0.03";
    uint64_t satoshi_amount_2;
    decode_base10(satoshi_amount_2, btc_amount_string_2, btc_decimal_places);
    output output_2(satoshi_amount_2, locking_script_2);


    //****************************************//
    // SIGHASH SINGLE chapter example begins here.

    // Not shown:
    // Construction of inputs and outputs.


    // We sign all inputs and single output with same index.
    tx.inputs().push_back(input_0);   //first input
    tx.outputs().push_back(output_0); //first output
    tx.inputs().push_back(input_1);   //second input
    tx.outputs().push_back(output_1); //second output
                                      //...nth input
                                      //...nth output

    // Construct previous output scripts of input_0 & input_1.
    script prevout_script0 = script::to_pay_key_hash_pattern(my_address0.hash());
    script prevout_script1 = script::to_pay_key_hash_pattern(my_address1.hash());

    // TX signature for input_0.
    endorsement sig_0;
    uint8_t input0_index(0u);
    script::create_endorsement(sig_0, my_secret0, prevout_script0, tx,
          input0_index, sighash_algorithm::single);

    // TX signature for input_1.
    endorsement sig_1;
    uint8_t input1_index(1u);
    script::create_endorsement(sig_1, my_secret1, prevout_script1, tx,
          input1_index, sighash_algorithm::single);

    // Construct input script_0.
    operation::list sig_script_0;
    sig_script_0.push_back(operation(sig_0));
    sig_script_0.push_back(operation(to_chunk(pubkey0)));
    script input_script0(sig_script_0);

    // Construct input script_1.
    operation::list sig_script_1;
    sig_script_1.push_back(operation(sig_1));
    sig_script_1.push_back(operation(to_chunk(pubkey1)));
    script input_script1(sig_script_1);

    // Add unlockingscript to TX.
    tx.inputs()[input0_index].set_script(input_script0);
    tx.inputs()[input1_index].set_script(input_script1);

    // SINGLE: We can add additional outputs after signing.
    tx.outputs().push_back(output_2); //third output
                                      //...nth output

    witness empty_witness;      // Only verified in a p2w tx.
    uint64_t prevout_amount(1); // Only verified in a p2w endorsement.

    // Verify input script (and endorsement) for input 0.
    auto ec_input0 = script::verify(tx, input0_index,rule_fork::all_rules,
          input_script0, empty_witness, prevout_script0,
          prevout_amount);

    // Success.
    std::cout << ec_input0.message() << std::endl;

    // Verify input script (and endorsement) for input 1.
    auto ec_input1 = script::verify(tx, input1_index,rule_fork::all_rules,
          input_script1, empty_witness, prevout_script1,
          prevout_amount);

    // Success.
    std::cout << ec_input1.message() << std::endl;

}


void sign_none_anyonecanpay() {

    // SETUP (IDENTICAL IN ALL EXAMPLES).
    // Private key, public keys.
    auto my_secret0 = base16_literal(
        "3eec08386d08321cd7143859e9bf4d6f65a71d24f37536d76b4224fdea48009f");
    auto my_secret1 = base16_literal(
        "86faa240ae2b0f28b125a42961bd3adf9d5f5dc6a1deaa5feda04e7be8c872f6");
    auto my_secret2 = base16_literal(
        "b7423c94ab99d3295c1af7e7bbea47c75d298f7190ca2077b53bae61299b70a5");
    auto my_secret3 = base16_literal(
        "d977e2ce0f744dc3432cde9813a99360a3f79f7c8035ef82310d54c57332b2cc");
    ec_private my_private0(my_secret0, ec_private::testnet, true); //compressed
    ec_private my_private1(my_secret1, ec_private::testnet, true); //compressed
    ec_private my_private2(my_secret2, ec_private::testnet, true); //compressed
    ec_private my_private3(my_secret3, ec_private::testnet, true); //compressed
    payment_address my_address0 = my_private0.to_payment_address();
    payment_address my_address1 = my_private1.to_payment_address();
    payment_address my_address2 = my_private2.to_payment_address();
    payment_address my_address3 = my_private3.to_payment_address();
    ec_compressed pubkey0 = my_private0.to_public().point();
    ec_compressed pubkey1 = my_private1.to_public().point();

    //Version.
    uint32_t version = 1u;
    transaction tx;
    tx.set_version(version);

    // Build input 0.
    std::string prev_tx_string_0 =
        "48828a16d0b93111272ec1721fceb29518efbd663c183e156873724ded5fe15d";
    hash_digest prev_tx_hash_0;
    decode_hash(prev_tx_hash_0,prev_tx_string_0);
    // Prevout index.
    uint32_t index0 = 0;
    output_point uxto_tospend_0(prev_tx_hash_0, index0);
    // Input object.
    input input_0;
    input_0.set_previous_output(uxto_tospend_0);
    input_0.set_sequence(max_input_sequence);
    // Build input 1.
    std::string prev_tx_string_1 =
        "e97db8ffd52711bbe012b7b1875e59106424dbfacd6938c688ca9535655c89ec";
    hash_digest prev_tx_hash_1;
    decode_hash(prev_tx_hash_1,prev_tx_string_1);
    // Prevout index.
    uint32_t index1 = 0;
    output_point uxto_tospend_1(prev_tx_hash_1, index1);
    // Input object.
    input input_1;
    input_1.set_previous_output(uxto_tospend_1);
    input_1.set_sequence(max_input_sequence);

    // Build output 0.
    operation::list locking_script_0 =
        script::to_pay_key_hash_pattern(my_address2.hash());
    std::string btc_amount_string_0 = "0.03";
    uint64_t satoshi_amount_0;
    decode_base10(satoshi_amount_0, btc_amount_string_0, btc_decimal_places);
    output output_0(satoshi_amount_0, locking_script_0);
    // Build output 1.
    operation::list locking_script_1 =
        script::to_pay_key_hash_pattern(my_address3.hash());
    std::string btc_amount_string_1 = "0.02";
    uint64_t satoshi_amount_1;
    decode_base10(satoshi_amount_1, btc_amount_string_1, btc_decimal_places);
    output output_1(satoshi_amount_1, locking_script_1);
    // Build locktime.

    //****************************************//
    // Specific setup for SIGHASH NONE|ANYONECANPAY example.
    // We prepare an endorsed input at index 1.

    // We create a TX copy for input_1 signing.
    transaction tx2 = tx;
    // Create previous script.
    script prevout_script1 = script::to_pay_key_hash_pattern(my_address1.hash());
    // Push input into TX2.
    input empty_input;
    tx2.inputs().push_back(empty_input); //A placeholder for input_0.
    tx2.inputs().push_back(input_1);
    // TX signature for input_1.
    endorsement sig_1;
    uint8_t input1_index(1u);
    script::create_endorsement(sig_1, my_secret1, prevout_script1, tx2,
        input1_index, none_anyone_can_pay);
    // Construct input script 1.
    operation::list sig_script_1;
    sig_script_1.push_back(operation(sig_1));
    sig_script_1.push_back(operation(to_chunk(pubkey1)));
    script input_script1(sig_script_1);
    input_1.set_script(input_script1);


    //****************************************//
    // SIGHASH NONE|ANYONECANPAY example.

    // Not shown:
    // Construction of inputs and outputs.

    // We only sign a single input.
    tx.inputs().push_back(input_0);

    // Construct previous output script of input_0.
    script prevout_script0 = script::to_pay_key_hash_pattern(my_address0.hash());

    // TX signature for input_0.
    endorsement sig_0;
    uint8_t input0_index(0u);
    script::create_endorsement(sig_0, my_secret0, prevout_script0, tx,
        input0_index, none_anyone_can_pay);

    // Construct input script_0.
    operation::list sig_script_0;
    sig_script_0.push_back(operation(sig_0));
    sig_script_0.push_back(operation(to_chunk(pubkey0)));
    script input_script0(sig_script_0);

    // Add unlockingscript to TX.
    tx.inputs()[input0_index].set_script(input_script0);

    // ANYONECANPAY: We can modify other inputs after signing.
    // Important: input added here must include valid input script!
    // ...and previously be signed with tx index = 1
    tx.inputs().push_back(input_1);   //second input
                                      //...nth input

    // NONE: We can modify all outputs after signing.
    tx.outputs().push_back(output_0); //first output
    tx.outputs().push_back(output_1); //second output
                                      //...nth output

    witness empty_witness;      // Only verified in a p2w tx.
    uint64_t prevout_amount(1); // Only verified in a p2w endorsement.

    // Verify input script (and endorsement) for input 0.
    auto ec_input0 = script::verify(tx, input0_index,rule_fork::all_rules,
          input_script0, empty_witness, prevout_script0,
          prevout_amount);

    // Success.
    std::cout << ec_input0.message() << std::endl;

    // Verify input script (and endorsement) for input 1.
    auto ec_input1 = script::verify(tx, input1_index,rule_fork::all_rules,
          input_script1, empty_witness, prevout_script1,
          prevout_amount);

    // Success.
    std::cout << ec_input1.message() << std::endl;


}


int main() {

  std::cout << "Signhash All Example: " << std::endl;
  sign_sighash_all();
  std::cout << "\n";

  std::cout << "Signhash NONE Example: " << std::endl;
  sign_sighash_none();
  std::cout << "\n";

  std::cout << "Signhash SINGLE Example: " << std::endl;
  sign_sighash_single();
  std::cout << "\n";

  std::cout << "Signhash NONE|ANYONECANPAY Example: " << std::endl;
  sign_none_anyonecanpay();
  std::cout << "\n";

  return 0;

}
#include "examples.h"

using namespace std;
using namespace seal;

void evaluate_polynomial_4th()
{
    print_example_banner("Example: CKKS Basics (1 + x + x^2 + x^3 + x^4)");

    size_t poly_modulus_degree = 16384;
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 40, 60 }));

    double scale = pow(2.0, 40);
    SEALContext context(parms);
    print_parameters(context);
    cout << endl;
    
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    vector<double> input;
    input.reserve(slot_count);
    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++)
    {
        input.push_back(curr_point);
        curr_point += step_size;
    }
    cout << "Input vector: " << endl;
    print_vector(input, 3, 7);

    Plaintext x_plain;
    encoder.encode(input, scale, x_plain);
    Ciphertext x_encrypted;
    encryptor.encrypt(x_plain, x_encrypted);
    cout << "x ok " << endl;
    cout << "[Scale] x1_encrypted : " << log2(x_encrypted.scale()) << " bits" << endl;
    cout << "[parms_id] x_encrypted : " << context.get_context_data(x_encrypted.parms_id())->chain_index() << endl;

    Ciphertext x2_encrypted, x3_encrypted, x4_encrypted;

    // x^2
    evaluator.square(x_encrypted, x2_encrypted);
    evaluator.relinearize_inplace(x2_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x2_encrypted);
    cout << "x2 ok " << endl;
    cout << "[Scale] x2_encrypted : " << log2(x2_encrypted.scale()) << " bits" << endl;
    cout << "[Scale] x1_encrypted : " << log2(x_encrypted.scale()) << " bits" << endl;
    cout << "[parms_id] x_encrypted : " << context.get_context_data(x_encrypted.parms_id())->chain_index() << endl;
    cout << "[parms_id] x2_encrypted : " << context.get_context_data(x2_encrypted.parms_id())->chain_index() << endl;

    // x^3 = x * x^2
    evaluator.mod_switch_to_inplace(x_encrypted, x2_encrypted.parms_id());
    evaluator.multiply(x_encrypted, x2_encrypted, x3_encrypted);
    evaluator.relinearize_inplace(x3_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x3_encrypted);

    cout << "[Scale] x3_encrypted : " << log2(x3_encrypted.scale()) << " bits" << endl;
    cout << "[parms_id] x_encrypted : " << context.get_context_data(x_encrypted.parms_id())->chain_index() << endl;
    cout << "[parms_id] x2_encrypted : " << context.get_context_data(x2_encrypted.parms_id())->chain_index() << endl;
    cout << "[parms_id] x3_encrypted : " << context.get_context_data(x3_encrypted.parms_id())->chain_index() << endl;

    // x^4 = x^2 * x^2
    evaluator.square(x2_encrypted, x4_encrypted);
    evaluator.relinearize_inplace(x4_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x4_encrypted);
    cout << "x4 ok " << endl;
    cout << "[Scale] x4_encrypted : " << log2(x4_encrypted.scale()) << " bits" << endl;
    cout << "[parms_id] x_encrypted : " << context.get_context_data(x_encrypted.parms_id())->chain_index() << endl;
    cout << "[parms_id] x2_encrypted : " << context.get_context_data(x2_encrypted.parms_id())->chain_index() << endl;
    cout << "[parms_id] x3_encrypted : " << context.get_context_data(x3_encrypted.parms_id())->chain_index() << endl;
    cout << "[parms_id] x4_encrypted : " << context.get_context_data(x4_encrypted.parms_id())->chain_index() << endl;


    // Encode constant 1
    Plaintext plain_coeff1;
    encoder.encode(1.0, scale, plain_coeff1);

    // Align encryption parameters
    parms_id_type last_parms_id = x4_encrypted.parms_id();
    evaluator.mod_switch_to_inplace(x_encrypted, last_parms_id);
    evaluator.mod_switch_to_inplace(x2_encrypted, last_parms_id);
    evaluator.mod_switch_to_inplace(x3_encrypted, last_parms_id);
    evaluator.mod_switch_to_inplace(plain_coeff1, last_parms_id);
    cout << "last_parms_id = x4_encrypted" << endl;
    cout << "[parms_id] x_encrypted : " << context.get_context_data(x_encrypted.parms_id())->chain_index() << endl;
    cout << "[parms_id] x2_encrypted : " << context.get_context_data(x2_encrypted.parms_id())->chain_index() << endl;
    cout << "[parms_id] x3_encrypted : " << context.get_context_data(x3_encrypted.parms_id())->chain_index() << endl;
    cout << "[parms_id] x4_encrypted : " << context.get_context_data(x4_encrypted.parms_id())->chain_index() << endl;


    // Ensure scale consistency
    x_encrypted.scale() = pow(2.0, 40);
    x2_encrypted.scale() = pow(2.0, 40);
    x3_encrypted.scale() = pow(2.0, 40);
    x4_encrypted.scale() = pow(2.0, 40);

    // Compute 1 + x + x^2 + x^3 + x^4
    Ciphertext encrypted_result;
    evaluator.add(x_encrypted, x2_encrypted, encrypted_result);
    evaluator.add_inplace(encrypted_result, x3_encrypted);
    evaluator.add_inplace(encrypted_result, x4_encrypted);
    evaluator.add_plain_inplace(encrypted_result, plain_coeff1);

    Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);

    cout << "Expected result:" << endl;
    vector<double> true_result;
    for (size_t i = 0; i < input.size(); i++)
    {
        double x = input[i];
        true_result.push_back(1.0 + x + x * x + x * x * x + x * x * x * x);
    }
    print_vector(true_result, 3, 7);

    cout << "Computed result:" << endl;
    print_vector(result, 3, 7);
}

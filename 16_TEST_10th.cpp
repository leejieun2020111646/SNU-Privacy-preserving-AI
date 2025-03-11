#include "examples.h"

using namespace std;
using namespace seal;

void evaluate_polynomial_10th()
{
    print_example_banner("Example: CKKS Basics (1 + x + x^2 + ... + x^10)");

    size_t poly_modulus_degree = 32768;
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 40, 40, 40, 60 }));

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

    // 1------------------------------------------------------------------------------------------
    Plaintext x_plain;
    encoder.encode(input, scale, x_plain);
    Ciphertext x_encrypted;
    encryptor.encrypt(x_plain, x_encrypted);
    cout << "x ok " << endl;

    Ciphertext x2_encrypted, x3_encrypted, x4_encrypted, x5_encrypted, x6_encrypted, x7_encrypted, x8_encrypted,
        x9_encrypted, x10_encrypted;

    // 2------------------------------------------------------------------------------------------
    evaluator.square(x_encrypted, x2_encrypted);
    evaluator.relinearize_inplace(x2_encrypted, relin_keys);
    
    evaluator.rescale_to_next_inplace(x2_encrypted);
    cout << "-----------------------------< x2 ok >-----------------------------" << endl;
    cout << "[Scale] x2_encrypted : " << log2(x2_encrypted.scale()) << " bits" << endl;
    cout << "[Scale] x1_encrypted : " << log2(x_encrypted.scale()) << " bits" << endl;
    cout << "[parms_id] x_encrypted : " << context.get_context_data(x_encrypted.parms_id())->chain_index() << endl;
    cout << "[parms_id] x2_encrypted : " << context.get_context_data(x2_encrypted.parms_id())->chain_index() << endl;

    evaluator.mod_switch_to_inplace(x_encrypted, x2_encrypted.parms_id());
    cout << "---after mod_switch_to_inplace---" << endl;
    cout << "[parms_id] x_encrypted : " << context.get_context_data(x_encrypted.parms_id())->chain_index() << endl;
    cout << "[parms_id] x2_encrypted : " << context.get_context_data(x2_encrypted.parms_id())->chain_index() << endl;

    // 3------------------------------------------------------------------------------------------
    evaluator.multiply(x_encrypted, x2_encrypted, x3_encrypted);
    evaluator.relinearize_inplace(x3_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x3_encrypted);
    cout << "-----------------------------< x3 ok >-----------------------------" << endl;
    cout << "[Scale] x2_encrypted : " << log2(x3_encrypted.scale()) << " bits" << endl;
    cout << "[parms_id] x_encrypted : " << context.get_context_data(x_encrypted.parms_id())->chain_index() << endl;
    cout << "[parms_id] x2_encrypted : " << context.get_context_data(x2_encrypted.parms_id())->chain_index() << endl;
    cout << "[parms_id] x3_encrypted : " << context.get_context_data(x3_encrypted.parms_id())->chain_index() << endl;
    // evaluator.mod_switch_to_inplace(x2_encrypted, x4_encrypted.parms_id());
    cout << "---after mod_switch_to_inplace---" << endl;
    cout << "[parms_id] x2_encrypted : " << context.get_context_data(x2_encrypted.parms_id())->chain_index() << endl;

    // 4------------------------------------------------------------------------------------------
    evaluator.square(x2_encrypted, x4_encrypted); // 그저 2제곱이므로 mod_switch 안함
    evaluator.relinearize_inplace(x4_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x4_encrypted);
    cout << "-----------------------------< x4 ok >-----------------------------" << endl;
    cout << "[Scale] x4_encrypted : " << log2(x4_encrypted.scale()) << " bits" << endl;
    cout << "[parms_id] x2_encrypted : " << context.get_context_data(x2_encrypted.parms_id())->chain_index() << endl;
    cout << "[parms_id] x4_encrypted : " << context.get_context_data(x4_encrypted.parms_id())->chain_index() << endl;
    evaluator.mod_switch_to_inplace(x_encrypted, x4_encrypted.parms_id());
    cout << "---after mod_switch_to_inplace---" << endl;
    cout << "[parms_id] x4_encrypted : " << context.get_context_data(x4_encrypted.parms_id())->chain_index() << endl;
    cout << "[parms_id] x_encrypted : " << context.get_context_data(x_encrypted.parms_id())->chain_index() << endl;

    // 5------------------------------------------------------------------------------------------
    // evaluator.mod_switch_to_inplace(x4_encrypted, x_encrypted.parms_id());
    // cout << "[parms_id] x_encrypted : " << context.get_context_data(x_encrypted.parms_id())->chain_index() << endl;
    // cout << "[parms_id] x4_encrypted : " << context.get_context_data(x4_encrypted.parms_id())->chain_index() << endl;

    evaluator.multiply(x_encrypted, x4_encrypted, x5_encrypted);
    evaluator.relinearize_inplace(x5_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x5_encrypted);
    cout << "-----------------------------< x5 ok >-----------------------------" << endl;
    cout << "[Scale] x5_encrypted : " << log2(x5_encrypted.scale()) << " bits" << endl;
    cout << "[parms_id] x3_encrypted : " << context.get_context_data(x3_encrypted.parms_id())->chain_index() << endl;
    cout << "[parms_id] x4_encrypted : " << context.get_context_data(x4_encrypted.parms_id())->chain_index() << endl;
    cout << "[parms_id] x5_encrypted : " << context.get_context_data(x5_encrypted.parms_id())->chain_index() << endl;
    // evaluator.mod_switch_to_inplace(x_encrypted, x4_encrypted.parms_id());
    // cout << "---after mod_switch_to_inplace---" << endl;
    // cout << "[parms_id] x5_encrypted : " << context.get_context_data(x5_encrypted.parms_id())->chain_index() << endl;

    // 6------------------------------------------------------------------------------------------
    evaluator.square(x3_encrypted, x6_encrypted);
    evaluator.relinearize_inplace(x6_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x6_encrypted);
    cout << "-----------------------------< x6 ok >-----------------------------" << endl;
    cout << "[Scale] x6_encrypted : " << log2(x6_encrypted.scale()) << " bits" << endl;
    cout << "[parms_id] x4_encrypted : " << context.get_context_data(x4_encrypted.parms_id())->chain_index() << endl;
    cout << "[parms_id] x5_encrypted : " << context.get_context_data(x5_encrypted.parms_id())->chain_index() << endl;
    cout << "[parms_id] x6_encrypted : " << context.get_context_data(x6_encrypted.parms_id())->chain_index() << endl;
    evaluator.mod_switch_to_inplace(x3_encrypted, x6_encrypted.parms_id());
    cout << "---after mod_switch_to_inplace---" << endl;
    cout << "[parms_id] x6_encrypted : " << context.get_context_data(x6_encrypted.parms_id())->chain_index() << endl;

    // 7------------------------------------------------------------------------------------------
    evaluator.mod_switch_to_inplace(x_encrypted, x6_encrypted.parms_id());
    cout << "---after mod_switch_to_inplace---" << endl;
    cout << "[parms_id] x7_encrypted : " << context.get_context_data(x_encrypted.parms_id())->chain_index() << endl;
    cout << "[parms_id] x7_encrypted : " << context.get_context_data(x6_encrypted.parms_id())->chain_index() << endl;

    evaluator.multiply(x_encrypted, x6_encrypted, x7_encrypted);
    evaluator.relinearize_inplace(x7_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x7_encrypted);
    cout << "-----------------------------< x7 ok >-----------------------------" << endl;
    cout << "[Scale] x7_encrypted : " << log2(x5_encrypted.scale()) << " bits" << endl;
    cout << "[parms_id] x6_encrypted : " << context.get_context_data(x6_encrypted.parms_id())->chain_index() << endl;
    cout << "[parms_id] x7_encrypted : " << context.get_context_data(x7_encrypted.parms_id())->chain_index() << endl;

    // 8------------------------------------------------------------------------------------------
    evaluator.square(x4_encrypted, x8_encrypted);
    evaluator.relinearize_inplace(x8_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x8_encrypted);
    cout << "-----------------------------< x8 ok >-----------------------------" << endl;

    // evaluator.mod_switch_to_inplace(x4_encrypted, x8_encrypted.parms_id());

    // 9------------------------------------------------------------------------------------------
    evaluator.mod_switch_to_inplace(x_encrypted, x8_encrypted.parms_id());
    cout << "[parms_id] x_encrypted : " << context.get_context_data(x_encrypted.parms_id())->chain_index() << endl;
    cout << "[parms_id] x8_encrypted : " << context.get_context_data(x8_encrypted.parms_id())->chain_index() << endl;

    evaluator.multiply(x_encrypted, x8_encrypted, x9_encrypted);
    evaluator.relinearize_inplace(x9_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x9_encrypted);
    cout << "-----------------------------< x9 ok >-----------------------------" << endl;

    cout << "[parms_id] x9_encrypted : " << context.get_context_data(x9_encrypted.parms_id())->chain_index() << endl;

    // 10-----------------------------------------------------------------------------------------

    evaluator.square(x5_encrypted, x10_encrypted);
    evaluator.relinearize_inplace(x10_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x10_encrypted);
    cout << "-----------------------------< x10 ok >-----------------------------" << endl;

    // Plaintext plain_coeff1;
    // encoder.encode(1.0, scale, plain_coeff1);
    vector<Plaintext> plain_coeffs(11); // 11개의 Plaintext 저장할 벡터
    vector<double> user_inputs(11); // 사용자 입력값 저장

    // 사용자 입력 받기
    for (int i = 0; i < 11; i++)
    {
        cout << "Enter value for plain_coeff" << i << ": ";
        cin >> user_inputs[i];
    }

    // 입력된 값을 인코딩하여 Plaintext에 저장
    for (int i = 0; i < 11; i++)
    {
        encoder.encode(user_inputs[i], scale, plain_coeffs[i]);
    }

    cout << "숫자 계수 Encoding completed." << endl;

    parms_id_type last_parms_id = x10_encrypted.parms_id();
    evaluator.mod_switch_to_inplace(x_encrypted, last_parms_id);
    evaluator.mod_switch_to_inplace(x2_encrypted, last_parms_id);
    evaluator.mod_switch_to_inplace(x3_encrypted, last_parms_id);
    evaluator.mod_switch_to_inplace(x4_encrypted, last_parms_id);
    evaluator.mod_switch_to_inplace(x5_encrypted, last_parms_id);
    evaluator.mod_switch_to_inplace(x6_encrypted, last_parms_id);
    evaluator.mod_switch_to_inplace(x7_encrypted, last_parms_id);
    evaluator.mod_switch_to_inplace(x8_encrypted, last_parms_id);
    evaluator.mod_switch_to_inplace(x9_encrypted, last_parms_id);
    // evaluator.mod_switch_to_inplace(plain_coeff1, last_parms_id);

    for (int i = 0; i < 11; i++)
    {
        evaluator.mod_switch_to_inplace(plain_coeffs[i], last_parms_id);
        cout << "계수 [parms_id] " << context.get_context_data(plain_coeffs[i].parms_id())->chain_index() << endl;
    }
    cout << "-----------------------------< 레벨맞추기 ok >-----------------------------" << endl;

    cout << "[parms_id] " << context.get_context_data(x_encrypted.parms_id())->chain_index() << endl;
    cout << "[parms_id] " << context.get_context_data(x2_encrypted.parms_id())->chain_index() << endl;
    cout << "[parms_id] " << context.get_context_data(x3_encrypted.parms_id())->chain_index() << endl;
    cout << "[parms_id] " << context.get_context_data(x4_encrypted.parms_id())->chain_index() << endl;
    cout << "[parms_id] " << context.get_context_data(x5_encrypted.parms_id())->chain_index() << endl;
    cout << "[parms_id] " << context.get_context_data(x6_encrypted.parms_id())->chain_index() << endl;
    cout << "[parms_id] " << context.get_context_data(x7_encrypted.parms_id())->chain_index() << endl;
    cout << "[parms_id] " << context.get_context_data(x8_encrypted.parms_id())->chain_index() << endl;
    cout << "[parms_id] " << context.get_context_data(x9_encrypted.parms_id())->chain_index() << endl;
    cout << "[parms_id] " << context.get_context_data(x10_encrypted.parms_id())->chain_index() << endl;
    // cout << "[parms_id] " << context.get_context_data(plain_coeff1.parms_id())->chain_index() << endl;

    x_encrypted.scale() = pow(2.0, 40);
    x2_encrypted.scale() = pow(2.0, 40);
    x3_encrypted.scale() = pow(2.0, 40);
    x4_encrypted.scale() = pow(2.0, 40);
    x5_encrypted.scale() = pow(2.0, 40);
    x6_encrypted.scale() = pow(2.0, 40);
    x7_encrypted.scale() = pow(2.0, 40);
    x8_encrypted.scale() = pow(2.0, 40);
    x9_encrypted.scale() = pow(2.0, 40);
    x10_encrypted.scale() = pow(2.0, 40);
    // plain_coeff1.scale() = pow(2.0, 40);
    for (int i = 0; i < 11; i++)
    {
        plain_coeffs[i].scale() = pow(2.0, 40);
    }

    evaluator.multiply_plain_inplace(x_encrypted, plain_coeffs[1]);
    evaluator.multiply_plain_inplace(x2_encrypted, plain_coeffs[2]);
    evaluator.multiply_plain_inplace(x3_encrypted, plain_coeffs[3]);
    evaluator.multiply_plain_inplace(x4_encrypted, plain_coeffs[4]);
    evaluator.multiply_plain_inplace(x5_encrypted, plain_coeffs[5]);
    evaluator.multiply_plain_inplace(x6_encrypted, plain_coeffs[6]);
    evaluator.multiply_plain_inplace(x7_encrypted, plain_coeffs[7]);
    evaluator.multiply_plain_inplace(x8_encrypted, plain_coeffs[8]);
    evaluator.multiply_plain_inplace(x9_encrypted, plain_coeffs[9]);
    evaluator.multiply_plain_inplace(x10_encrypted, plain_coeffs[10]);
    cout << "plain_coeffs[1] 곱한거 잘 되긴 함" << endl;
    cout << "[x parms_id] " << context.get_context_data(x_encrypted.parms_id())->chain_index() << endl;
    cout << "[Scale] x_encrypted : " << log2(x_encrypted.scale()) << " bits" << endl;
    cout << "[Scale] x2_encrypted : " << log2(x2_encrypted.scale()) << " bits" << endl;
    cout << "[Scale] plain_coeffs[0] : " << log2(plain_coeffs[0].scale()) << " bits" << endl;
    x_encrypted.scale() = pow(2.0, 40);
    x2_encrypted.scale() = pow(2.0, 40);
    x3_encrypted.scale() = pow(2.0, 40);
    x4_encrypted.scale() = pow(2.0, 40);
    x5_encrypted.scale() = pow(2.0, 40);
    x6_encrypted.scale() = pow(2.0, 40);
    x7_encrypted.scale() = pow(2.0, 40);
    x8_encrypted.scale() = pow(2.0, 40);
    x9_encrypted.scale() = pow(2.0, 40);
    x10_encrypted.scale() = pow(2.0, 40);

    Ciphertext encrypted_result;
    evaluator.add(x_encrypted, x2_encrypted, encrypted_result);
    cout << "evaluator.add(x_encrypted, x2_encrypted, encrypted_result);" << endl;
    evaluator.add_inplace(encrypted_result, x3_encrypted);
    evaluator.add_inplace(encrypted_result, x4_encrypted);
    evaluator.add_inplace(encrypted_result, x5_encrypted);
    evaluator.add_inplace(encrypted_result, x6_encrypted);
    evaluator.add_inplace(encrypted_result, x7_encrypted);
    cout << "evaluator.add_inplace(encrypted_result, x7_encrypted);" << endl;
    evaluator.add_inplace(encrypted_result, x8_encrypted);
    evaluator.add_inplace(encrypted_result, x9_encrypted);
    evaluator.add_inplace(encrypted_result, x10_encrypted);
    evaluator.add_plain_inplace(encrypted_result, plain_coeffs[0]);
    cout << "-----------------------------< 더하기 ok >-----------------------------" << endl;

    Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);

    cout << "Computed result:" << endl;
    print_vector(result, 3, 7);
}

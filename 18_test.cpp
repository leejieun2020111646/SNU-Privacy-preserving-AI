// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

void evaluate_polynomial_18()
{
    print_example_banner("Example: CKKS Automated Polynomial Evaluation");

    size_t poly_modulus_degree = 32768; // 65536; // 32768;

    EncryptionParameters parms(scheme_type::ckks);

    parms.set_poly_modulus_degree(poly_modulus_degree);

    parms.set_coeff_modulus(

        CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40,
                                                    40, 40, 40, 40, 60 }));

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

    vector<double> input(slot_count);

    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);

    for (size_t i = 0; i < slot_count; i++)

    {
        input[i] = i * step_size;
    }

    cout << "Input vector: " << endl;

    print_vector(input, 3, 7);

    // 사용자로부터 다항식의 차수를 입력받음

    int degree;

    cout << "몇 차 다항식을 평가할래?: ";

    cin >> degree;

    if (degree < 1)

    {
        cout << "차수는 1 이상이어야 합니다." << endl;

        return;
    }

    // 암호화된 x^1부터 x^degree까지 저장할 벡터

    vector<Ciphertext> x_encrypted(degree + 1);

    Plaintext x_plain;

    encoder.encode(input, scale, x_plain);

    encryptor.encrypt(x_plain, x_encrypted[1]); // x^1 암호화

    cout << "x ok" << endl;

    // x^2부터 x^degree까지 계산

    for (int i = 2; i <= degree; i++)

    {
        if (i % 2 == 0) // 짝수 차수 (제곱 연산)

        {
            evaluator.square(x_encrypted[i / 2], x_encrypted[i]);
        }

        else // 홀수 차수 (곱셈 연산)

        {
            evaluator.mod_switch_to_inplace(x_encrypted[1], x_encrypted[i - 1].parms_id());

            evaluator.multiply(x_encrypted[1], x_encrypted[i - 1], x_encrypted[i]);
        }

        evaluator.relinearize_inplace(x_encrypted[i], relin_keys);

        evaluator.rescale_to_next_inplace(x_encrypted[i]);

        cout << "[Scale] x" << i << "_encrypted : " << log2(x_encrypted[i].scale()) << " bits" << endl;

        cout << "[parms_id] x" << i

             << "_encrypted : " << context.get_context_data(x_encrypted[i].parms_id())->chain_index() << endl;

        cout << "-----------------------------< x" << i << " ok >-----------------------------" << endl;
    }
    Plaintext x_plain_result;
    vector<double> reslt;
    decryptor.decrypt(x_encrypted[3], x_plain_result);
    encoder.decode(x_plain_result, reslt);
    print_vector(reslt, 3, 7);

    // 사용자 입력 계수 저장

    vector<Plaintext> plain_coeffs(degree + 1);

    vector<double> user_inputs(degree + 1);

    for (int i = 0; i <= degree; i++)

    {
        cout << "Enter value for plain_coeff" << i << ": ";

        cin >> user_inputs[i];

        encoder.encode(user_inputs[i], scale, plain_coeffs[i]);
    }

    cout << "숫자 계수 Encoding completed." << endl;
    encoder.decode(plain_coeffs[0], reslt);
    print_vector(reslt, 3, 7);

    // 레벨 맞추기

    parms_id_type last_parms_id = x_encrypted[degree].parms_id();

    for (int i = 1; i <= degree; i++)

    {
        evaluator.mod_switch_to_inplace(x_encrypted[i], last_parms_id);
    }

    for (int i = 0; i <= degree; i++)

    {
        evaluator.mod_switch_to_inplace(plain_coeffs[i], last_parms_id);

        plain_coeffs[i].scale() = pow(2.0, 40);
    }

    cout << "-----------------------------< 레벨맞추기 ok >-----------------------------" << endl;

    // 계수 곱하기///

    for (int i = 1; i <= degree; i++)

    {
        evaluator.multiply_plain_inplace(x_encrypted[i], plain_coeffs[i]);
        // 새로 추가한 부분. rescale 이 빠져있었음. 큰 숫자가 나온 이유가 이것 때문인듯
        evaluator.rescale_to_next_inplace(x_encrypted[i]);
        x_encrypted[i].scale() = pow(2.0, 40);
    }

    cout << "Coefficients multiplied successfully." << endl;

    // // 덧셈 전에 parms_id() 맞추기 --> 이미 다 맞춰져 있어서 할 필요없음

    // for (int i = 1; i <= degree; i++)

    // {

    //     evaluator.mod_switch_to_inplace(x_encrypted[i], last_parms_id);

    // }

    // 새로 추가한 부분. 상수항은 아직 레벨 안 맞춰져있어서 추가 했음
    evaluator.mod_switch_to_inplace(plain_coeffs[0], x_encrypted[1].parms_id());

    // 결과 합산

    Ciphertext encrypted_result = x_encrypted[1];

    for (int i = 2; i <= degree; i++)

    {
        evaluator.add_inplace(encrypted_result, x_encrypted[i]);
    }

    evaluator.add_plain_inplace(encrypted_result, plain_coeffs[0]);

    cout << "-----------------------------< 더하기 ok >-----------------------------" << endl;

    // 복호화 및 결과 출력

    Plaintext plain_result;

    decryptor.decrypt(encrypted_result, plain_result);

    vector<double> result;

    encoder.decode(plain_result, result);

    cout << "최종 결과:" << endl;

    print_vector(result, 3, 7);
}

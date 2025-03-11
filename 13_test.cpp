#include "seal/seal.h"
#include <iomanip>
#include <iostream>

using namespace seal;
using namespace std;

void example_to_test()
{
    // ��ȣȭ �Ķ���� ����
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    SEALContext context(parms);

    if (!context.parameters_set())
    {
        cout << "Invalid encryption parameters!" << endl;
        return;
    }

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    double scale = pow(2.0, 40);

    // �� �Ǽ� �Է¹ޱ�
    double num1, num2;
    cout << "Enter the first number: ";
    cin >> num1;
    cout << "Enter the second number: ";
    cin >> num2;

    // �Է°� ���ڵ� �� ��ȣȭ
    Plaintext plain_num1, plain_num2;
    encoder.encode(num1, scale, plain_num1);
    encoder.encode(num2, scale, plain_num2);

    Ciphertext encrypted_num1, encrypted_num2;
    encryptor.encrypt(plain_num1, encrypted_num1);
    encryptor.encrypt(plain_num2, encrypted_num2);

    // ���� ����
    Ciphertext encrypted_sum;
    evaluator.add(encrypted_num1, encrypted_num2, encrypted_sum);

    // ���� ����
    Ciphertext encrypted_product;
    evaluator.multiply(encrypted_num1, encrypted_num2, encrypted_product);
    evaluator.relinearize_inplace(encrypted_product, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_product);

    // ��ȣȭ �� ��� Ȯ��
    Plaintext plain_sum, plain_product;
    decryptor.decrypt(encrypted_sum, plain_sum);
    decryptor.decrypt(encrypted_product, plain_product);

    vector<double> decoded_sum, decoded_product;
    encoder.decode(plain_sum, decoded_sum);
    encoder.decode(plain_product, decoded_product);

    // ���� ���
    double result_sum = decoded_sum[0];
    double result_product = decoded_product[0];

    // ���� ���
    double expected_sum = num1 + num2;
    double expected_product = num1 * num2;

    // ���� ���
    double absolute_error_sum = fabs(result_sum - expected_sum);
    double absolute_error_product = fabs(result_product - expected_product);

    // ��� ���
    cout << fixed << setprecision(20);
    cout << "\n���:" << endl;
    cout << "Addition:" << endl;
    cout << "  ���� ��ȣȭ ���: " << result_sum << endl;
    cout << "  ���� ���: " << expected_sum << endl;
    cout << "  ����: " << absolute_error_sum << endl;

    cout << "\nMultiplication:" << endl;
    cout << "  ���� ��ȣȭ ���: " << result_product << endl;
    cout << "  ���� ���: " << expected_product << endl;
    cout << "  ����: " << absolute_error_product << endl;
}
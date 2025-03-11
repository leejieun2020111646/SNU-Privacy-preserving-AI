#include <iomanip> //��� ���� ���� ���� ���(�Ҽ��� �ڸ��� ���� ��)
#include "examples.h"

using namespace seal;
using namespace std;

void example_multiply_vector_matrix_4()
{
    // ���� ���� ��� ���� �����Լ�
    auto print_vector = [](string title, const vector<double> &vec, size_t print_size) {
        cout << title << ": ";
        for (size_t i = 0; i < print_size && i < vec.size(); i++)
        {
            cout << fixed << setprecision(1) << vec[i] << " "; // �Ҽ��� 1�ڸ� ���
        }
        cout << endl;
    };

    // ��ȣȭ �Ķ���� ����
    EncryptionParameters parms(scheme_type::ckks); // CKKS ���
    size_t poly_modulus_degree = 8192; // ���׽� ���� (8192 ���� ���)
    parms.set_poly_modulus_degree(poly_modulus_degree); // ���׽� ���� ����
    parms.set_coeff_modulus(
        CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 })); // ��� ��ⷯ�� ���� (�� 200��Ʈ)

    SEALContext context(parms);
    print_parameters(context); // ��ȣȭ �Ķ���� ���

    // Ű ����
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key(); // ���Ű
    PublicKey public_key;
    keygen.create_public_key(public_key); // ����Ű
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys); // �缱��ȭ
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys); // rotation ���� Galois Ű ����

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context); // �� ��ü(���� ���� ����)
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    double scale = pow(2.0, 40); // ������ ���� (���� ���е�)
    size_t slot_count = encoder.slot_count(); // ��� ������ ���� ���� Ȯ��
    size_t vector_size = 4; // �Էº��� �� ��� ũ��(4x4 ���)

    // �Է� ���� �� ��� ����
    vector<double> input_vector = { 1.0, 2.0, 3.0, 4.0 };
    vector<vector<double>> matrix = {
        { 1.0, 2.0, 3.0, 4.0 }, { 5.0, 6.0, 7.0, 8.0 }, { 9.0, 10.0, 11.0, 12.0 }, { 13.0, 14.0, 15.0, 16.0 }
    };

    // �Է� ���͸� CKKS ���� ũ�⿡ �°� Ȯ��
    vector<double> input_vector_extended = input_vector;
    input_vector_extended.resize(slot_count, 0.0); //(������ ������ 0���� ä��)

    // �Է� ���͸� ������ ���ڵ�
    Plaintext plain_vector;
    encoder.encode(input_vector_extended, scale, plain_vector);

    // �Է� ���� ��ȣȭ
    Ciphertext encrypted_vector;
    encryptor.encrypt(plain_vector, encrypted_vector);

    // ��� ����� ����
    vector<Ciphertext> row_results;

    // �� �࿡ ���� ���� ����
    for (size_t i = 0; i < vector_size; i++)
    {
        vector<double> row = matrix[i]; // ���� �� ����
        row.resize(slot_count, 0.0);
        // ����(����� �� ��)�� ũ�⸦ ���� ũ�⿡ �°� Ȯ��(CKKS ������ ��ü ������ ������� ����ǹǷ�)

        // ���� ������ ���ڵ�
        Plaintext plain_row;
        encoder.encode(row, scale, plain_row);
        // �� ��ȣȭ
        Ciphertext encrypted_row;
        encryptor.encrypt(plain_row, encrypted_row);
        // �Է� ���Ϳ� ���� ���� �� ���
        Ciphertext temp;
        evaluator.multiply_plain(encrypted_vector, plain_row, temp); // ��ȣȭ�� ���Ϳ� ���� ���� ���
        evaluator.rescale_to_next_inplace(temp); // ���� �� �������ϸ�

        // ������ �缳��
        // CKKS������ ��ȣ������ ���� �������� ������
        temp.scale() = scale;

        // ȸ�� ��� ���� �ջ�
        Ciphertext sum = temp;
        for (size_t rot = 1; rot < vector_size; rot++)
        {
            Ciphertext rotated;
            evaluator.rotate_vector(temp, rot, galois_keys, rotated); // ���� ȸ��
            evaluator.add_inplace(sum, rotated); // ���� �� �ջ�
        }

        row_results.push_back(sum); // ���� ���� ȸ�� ��� ����
    }

    // ���� ��� ���
    cout << "\\nFinal Results:" << endl;
    for (size_t i = 0; i < row_results.size(); i++)
    {
        // ��� ��ȣȭ
        Plaintext decrypted_result;
        decryptor.decrypt(row_results[i], decrypted_result);
        vector<double> decoded_result;
        encoder.decode(decrypted_result, decoded_result); // ��ȣȭ�� �� ���ڵ�

        // ������ ��µǾ�� �� ���� �� ���
        double expected = 0.0;
        for (size_t j = 0; j < vector_size; j++)
        {
            expected += input_vector[j] * matrix[i][j];
        }

        // ��� ���
        cout << "\\nRow " << i << ":" << endl;
        cout << "Encrypted result (decoded): " << decoded_result[0] << setprecision(10) << endl;
        cout << "Expected result: " << expected << endl;
        cout << "Difference: " << (decoded_result[0] - expected) << endl; // ���� ���(����)
    }
}
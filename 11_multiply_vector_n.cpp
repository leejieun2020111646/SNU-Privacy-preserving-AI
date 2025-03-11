#include <iomanip> // ��� ���� ���� ���� ���
#include "examples.h"

using namespace seal;
using namespace std;

void example_multiply_vector_matrix_dynamic()
{
    // ���� ��¿� ���� �Լ�
    auto print_vector = [](string title, const vector<double> &vec, size_t print_size) {
        cout << title << ": ";
        for (size_t i = 0; i < print_size && i < vec.size(); i++)
        {
            cout << fixed << setprecision(1) << vec[i] << " ";
        }
        cout << endl;
    };

    // ����� �Է� �ޱ�
    size_t vector_size;
    cout << "Enter the dimension (N) of the vector and matrix: ";
    cin >> vector_size;

    // ��ȣȭ �Ķ���� ����
    EncryptionParameters parms(scheme_type::ckks); // CKKS ���
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    SEALContext context(parms);
    print_parameters(context);

    // Ű ����
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys); // rotation ���� Galois Ű ����

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context); // �� ��ü(���� ���� ����)
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    double scale = pow(2.0, 40);
    size_t slot_count = encoder.slot_count(); // ��� ������ ���� ���� Ȯ��

    // �Է� ���� �� ��� ����
    vector<double> input_vector(vector_size);
    vector<vector<double>> matrix(vector_size, vector<double>(vector_size));

    for (size_t i = 0; i < vector_size; i++)
    {
        input_vector[i] = static_cast<double>(i + 1); // {1.0, 2.0, ..., N}
        for (size_t j = 0; j < vector_size; j++)
        {
            matrix[i][j] = static_cast<double>((i * vector_size) + (j + 1)); // ��� �� ����
        }
    }

    // ���Ϳ� ��� ���
    print_vector("Input Vector", input_vector, vector_size);
    cout << "Matrix: " << endl;
    for (const auto &row : matrix)
    {
        print_vector("", row, vector_size);
    }

    // �Է� ���͸� CKKS ���� ũ�⿡ �°� Ȯ��
    vector<double> input_vector_extended = input_vector;
    input_vector_extended.resize(slot_count, 0.0); // ���� ũ�⿡ �°� Ȯ��

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
        row.resize(slot_count, 0.0); // ���� ũ�⿡ �°� Ȯ��

        // ���� ������ ���ڵ�
        Plaintext plain_row;
        encoder.encode(row, scale, plain_row);

        // �� ��ȣȭ �� ����
        Ciphertext temp;
        evaluator.multiply_plain(encrypted_vector, plain_row, temp);
        evaluator.rescale_to_next_inplace(temp); // ���� �� �������ϸ�

        // ���� ��� ���
        Plaintext debug_plain;
        decryptor.decrypt(temp, debug_plain);
        vector<double> debug_result;
        encoder.decode(debug_plain, debug_result);
        cout << i << "��° �� ���� ���: ";
        print_vector("", debug_result, vector_size);

        // ������ �缳��
        temp.scale() = scale;

        // ȸ�� ��� ���� �ջ�
        Ciphertext sum = temp;
        for (size_t rot = 1; rot < vector_size; rot++)
        {
            Ciphertext rotated;
            evaluator.rotate_vector(temp, rot, galois_keys, rotated); // ���� ȸ��

            // ȸ�� ��� ���
            decryptor.decrypt(rotated, debug_plain);
            encoder.decode(debug_plain, debug_result);
            cout << i + 1 << " ��° �� " << rot << " ȸ�� �� : ";
            print_vector("", debug_result, vector_size);

            evaluator.add_inplace(sum, rotated); // ���� �ջ�
        }

        row_results.push_back(sum); // ���� ���� ȸ�� ��� ����
    }

    // ���� ��� ���
    cout << "\nFinal Results:" << endl;
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

        cout << "\nRow " << i << ":" << endl;
        cout << "Derypted result (decoded): " << decoded_result[0] << setprecision(10) << endl;
        cout << "Expected result: " << expected << endl;
        cout << "Difference: " << (decoded_result[0] - expected) << endl;
    }
}

#include <iomanip>
#include "examples.h"

using namespace seal;
using namespace std;

void example_multiply_matrix_matrix_dynamic()
{
    // ���� ��� �� ����
    auto print_matrix = [](string title, const vector<vector<double>> &matrix) {
        cout << title << ":" << endl;
        for (const auto &row : matrix)
        {
            for (const auto &val : row)
            {
                cout << fixed << setprecision(1) << val << " ";
            }
            cout << endl;
        }
    };

    // ��� ũ�� �Է¹���: (NxM) * (MxK) ��
    size_t N, M, K;
    cout << "Enter the dimensions (N, M, K) for matrix multiplication (NxM) * (MxK): ";
    cin >> N >> M >> K;

    // ��ȣȭ �Ķ���� ����
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192; // ���� ũ�� ����
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    SEALContext context(parms);

    // (�Ķ���� ��ȿ�� �˻� �߰�)
    if (!context.parameters_set())
    {
        cout << "Invalid encryption parameters!" << endl;
        return;
    }

    // Ű ����
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    // GaloisKeys ����
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    // ������ �� ���� ũ�� ����
    double scale = pow(2.0, 40);
    size_t slot_count = encoder.slot_count();

    // ���1 (NxM) �ʱ�ȭ(1.0 ~ �� ä��)
    vector<vector<double>> matrix_A(N, vector<double>(M, 0.0));
    for (size_t i = 0; i < N; i++)
    {
        for (size_t j = 0; j < M; j++)
        {
            matrix_A[i][j] = static_cast<double>(i + j + 1); 
        }
    }

    // ���2 (MxK) �ʱ�ȭ
    vector<vector<double>> matrix_B(M, vector<double>(K, 0.0));
    for (size_t i = 0; i < M; i++)
    {
        for (size_t j = 0; j < K; j++)
        {
            matrix_B[i][j] = static_cast<double>(i + j + 1);
        }
    }

    print_matrix("Matrix A", matrix_A);
    print_matrix("Matrix B", matrix_B);

    // ��� 1�� �� �� ��ȣȭ
    vector<Ciphertext> encrypted_matrix_A(N);
    for (size_t i = 0; i < N; i++)
    {
        vector<double> row(slot_count, 0.0);
        copy(matrix_A[i].begin(), matrix_A[i].end(), row.begin()); // ���� ���Կ� �����ص�
        Plaintext plain_row;
        encoder.encode(row, scale, plain_row);
        encryptor.encrypt(plain_row, encrypted_matrix_A[i]); // ��ȣȭ �� ����
    }

    // ���2 �� ���� ��ȣȭ
    vector<Ciphertext> encrypted_matrix_B(K);
    for (size_t j = 0; j < K; j++)
    {
        vector<double> col(slot_count, 0.0);
        for (size_t i = 0; i < M; i++)
        {
            col[i] = matrix_B[i][j]; // ���� ���Կ� ����
        }
        Plaintext plain_col;
        encoder.encode(col, scale, plain_col);
        encryptor.encrypt(plain_col, encrypted_matrix_B[j]);
    }

    // Print encrypted_matrix_B for debugging
    cout << "Encrypted Matrix B (Ciphertexts):" << endl;
    for (size_t j = 0; j < K; j++)
    {
        cout << "Encrypted column " << j << ": parms_id = " << encrypted_matrix_B[j].parms_id()
             << ", size = " << encrypted_matrix_B[j].size() << endl;
    }

    // ��� ��� (NxK) �ʱ�ȭ
    vector<vector<double>> result_matrix(N, vector<double>(K, 0.0));

    // ��� ���� ����
    for (size_t i = 0; i < N; i++)
    {
        for (size_t j = 0; j < K; j++)
        {
            // ���1�� i��° ��� ���2�� j��° ���� ���� ���
            Ciphertext dot_product;
            evaluator.multiply(encrypted_matrix_A[i], encrypted_matrix_B[j], dot_product);

            evaluator.relinearize_inplace(dot_product, relin_keys);
            evaluator.rescale_to_next_inplace(dot_product);

            // rotation �� �ջ�
            Ciphertext sum = dot_product;
            for (size_t rot = 1; rot < M; rot++)
            {
                Ciphertext rotated;
                evaluator.rotate_vector(dot_product, rot, galois_keys, rotated);
                evaluator.add_inplace(sum, rotated);
            }

            // ��ȣȭ �� ���ڵ�
            Plaintext plain_result;
            decryptor.decrypt(sum, plain_result);
            vector<double> decoded_result;
            encoder.decode(plain_result, decoded_result);

            // ��� ����
            result_matrix[i][j] = decoded_result[0];

            // ���� ���� �� ���
            double expected = 0.0;
            for (size_t k = 0; k < M; k++)
            {
                expected += matrix_A[i][k] * matrix_B[k][j];
            }

            // ���� ���
            double absolute_error = fabs(decoded_result[0] - expected);
            double relative_error = (expected != 0.0) ? fabs(absolute_error / expected) : 0.0;

            // ��� ���
            cout << fixed << setprecision(20);
            cout << "Result[" << i << "][" << j << "]:" << endl;
            cout << "  Encrypted result (decoded): " << decoded_result[0] << endl;
            cout << "  Expected result: " << expected << endl;
            cout << "  ����: " << absolute_error << endl;
            
        }
    }


    // ���� ��� ��� ���
    cout << "--------------------------" << endl;
    print_matrix("Result Matrix (A * B)", result_matrix);
}

#include <iomanip> // 출력 포맷 조정 위한 헤더
#include "examples.h"

using namespace seal;
using namespace std;

void example_multiply_vector_matrix_dynamic()
{
    // 벡터 출력용 람다 함수
    auto print_vector = [](string title, const vector<double> &vec, size_t print_size) {
        cout << title << ": ";
        for (size_t i = 0; i < print_size && i < vec.size(); i++)
        {
            cout << fixed << setprecision(1) << vec[i] << " ";
        }
        cout << endl;
    };

    // 사용자 입력 받기
    size_t vector_size;
    cout << "Enter the dimension (N) of the vector and matrix: ";
    cin >> vector_size;

    // 암호화 파라미터 설정
    EncryptionParameters parms(scheme_type::ckks); // CKKS 사용
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    SEALContext context(parms);
    print_parameters(context);

    // 키 생성
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys); // rotation 위한 Galois 키 생성

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context); // 평가 객체(동형 연산 수행)
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    double scale = pow(2.0, 40);
    size_t slot_count = encoder.slot_count(); // 사용 가능한 슬롯 개수 확인

    // 입력 벡터 및 행렬 생성
    vector<double> input_vector(vector_size);
    vector<vector<double>> matrix(vector_size, vector<double>(vector_size));

    for (size_t i = 0; i < vector_size; i++)
    {
        input_vector[i] = static_cast<double>(i + 1); // {1.0, 2.0, ..., N}
        for (size_t j = 0; j < vector_size; j++)
        {
            matrix[i][j] = static_cast<double>((i * vector_size) + (j + 1)); // 행렬 값 생성
        }
    }

    // 벡터와 행렬 출력
    print_vector("Input Vector", input_vector, vector_size);
    cout << "Matrix: " << endl;
    for (const auto &row : matrix)
    {
        print_vector("", row, vector_size);
    }

    // 입력 벡터를 CKKS 슬롯 크기에 맞게 확장
    vector<double> input_vector_extended = input_vector;
    input_vector_extended.resize(slot_count, 0.0); // 슬롯 크기에 맞게 확장

    // 입력 벡터를 평문으로 인코딩
    Plaintext plain_vector;
    encoder.encode(input_vector_extended, scale, plain_vector);

    // 입력 벡터 암호화
    Ciphertext encrypted_vector;
    encryptor.encrypt(plain_vector, encrypted_vector);

    // 결과 저장용 벡터
    vector<Ciphertext> row_results;

    // 각 행에 대해 연산 수행
    for (size_t i = 0; i < vector_size; i++)
    {
        vector<double> row = matrix[i]; // 현재 행 추출
        row.resize(slot_count, 0.0); // 슬롯 크기에 맞게 확장

        // 행을 평문으로 인코딩
        Plaintext plain_row;
        encoder.encode(row, scale, plain_row);

        // 행 암호화 및 곱셈
        Ciphertext temp;
        evaluator.multiply_plain(encrypted_vector, plain_row, temp);
        evaluator.rescale_to_next_inplace(temp); // 곱셈 후 리스케일링

        // 곱셈 결과 출력
        Plaintext debug_plain;
        decryptor.decrypt(temp, debug_plain);
        vector<double> debug_result;
        encoder.decode(debug_plain, debug_result);
        cout << i << "번째 행 곱셈 결과: ";
        print_vector("", debug_result, vector_size);

        // 스케일 재설정
        temp.scale() = scale;

        // 회전 결과 누적 합산
        Ciphertext sum = temp;
        for (size_t rot = 1; rot < vector_size; rot++)
        {
            Ciphertext rotated;
            evaluator.rotate_vector(temp, rot, galois_keys, rotated); // 벡터 회전

            // 회전 결과 출력
            decryptor.decrypt(rotated, debug_plain);
            encoder.decode(debug_plain, debug_result);
            cout << i + 1 << " 번째 행 " << rot << " 회전 후 : ";
            print_vector("", debug_result, vector_size);

            evaluator.add_inplace(sum, rotated); // 누적 합산
        }

        row_results.push_back(sum); // 현재 행의 회전 결과 저장
    }

    // 최종 결과 출력
    cout << "\nFinal Results:" << endl;
    for (size_t i = 0; i < row_results.size(); i++)
    {
        // 결과 복호화
        Plaintext decrypted_result;
        decryptor.decrypt(row_results[i], decrypted_result);
        vector<double> decoded_result;
        encoder.decode(decrypted_result, decoded_result); // 복호화된 값 디코딩

        // 기존의 출력되어야 할 내적 값 계산
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

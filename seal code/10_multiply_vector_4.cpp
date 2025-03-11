#include <iomanip> //출력 포맷 조정 위한 헤더(소수점 자리수 조정 등)
#include "examples.h"

using namespace seal;
using namespace std;

void example_multiply_vector_matrix_4()
{
    // 벡터 내용 출력 위한 람다함수
    auto print_vector = [](string title, const vector<double> &vec, size_t print_size) {
        cout << title << ": ";
        for (size_t i = 0; i < print_size && i < vec.size(); i++)
        {
            cout << fixed << setprecision(1) << vec[i] << " "; // 소수점 1자리 출력
        }
        cout << endl;
    };

    // 암호화 파라미터 설정
    EncryptionParameters parms(scheme_type::ckks); // CKKS 사용
    size_t poly_modulus_degree = 8192; // 다항식 차수 (8192 슬롯 사용)
    parms.set_poly_modulus_degree(poly_modulus_degree); // 다항식 차수 설정
    parms.set_coeff_modulus(
        CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 })); // 계수 모듈러스 설정 (총 200비트)

    SEALContext context(parms);
    print_parameters(context); // 암호화 파라미터 출력

    // 키 생성
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key(); // 비밀키
    PublicKey public_key;
    keygen.create_public_key(public_key); // 공개키
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys); // 재선형화
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys); // rotation 위한 Galois 키 생성

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context); // 평가 객체(동형 연산 수행)
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    double scale = pow(2.0, 40); // 스케일 설정 (연산 정밀도)
    size_t slot_count = encoder.slot_count(); // 사용 가능한 슬롯 개수 확인
    size_t vector_size = 4; // 입력벡터 및 행렬 크기(4x4 행렬)

    // 입력 벡터 및 행렬 정의
    vector<double> input_vector = { 1.0, 2.0, 3.0, 4.0 };
    vector<vector<double>> matrix = {
        { 1.0, 2.0, 3.0, 4.0 }, { 5.0, 6.0, 7.0, 8.0 }, { 9.0, 10.0, 11.0, 12.0 }, { 13.0, 14.0, 15.0, 16.0 }
    };

    // 입력 벡터를 CKKS 슬롯 크기에 맞게 확장
    vector<double> input_vector_extended = input_vector;
    input_vector_extended.resize(slot_count, 0.0); //(나머지 슬롯은 0으로 채움)

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
        row.resize(slot_count, 0.0);
        // 벡터(행렬의 한 행)의 크기를 슬롯 크기에 맞게 확장(CKKS 연산은 전체 슬롯을 대상으로 수행되므로)

        // 행을 평문으로 인코딩
        Plaintext plain_row;
        encoder.encode(row, scale, plain_row);
        // 행 암호화
        Ciphertext encrypted_row;
        encryptor.encrypt(plain_row, encrypted_row);
        // 입력 벡터와 현재 행의 곱 계산
        Ciphertext temp;
        evaluator.multiply_plain(encrypted_vector, plain_row, temp); // 암호화된 벡터와 행의 내적 계산
        evaluator.rescale_to_next_inplace(temp); // 곱셈 후 리스케일링

        // 스케일 재설정
        // CKKS에서는 암호문들이 같은 스케일을 가져야
        temp.scale() = scale;

        // 회전 결과 누적 합산
        Ciphertext sum = temp;
        for (size_t rot = 1; rot < vector_size; rot++)
        {
            Ciphertext rotated;
            evaluator.rotate_vector(temp, rot, galois_keys, rotated); // 벡터 회전
            evaluator.add_inplace(sum, rotated); // 누적 값 합산
        }

        row_results.push_back(sum); // 현재 행의 회전 결과 저장
    }

    // 최종 결과 출력
    cout << "\\nFinal Results:" << endl;
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

        // 결과 출력
        cout << "\\nRow " << i << ":" << endl;
        cout << "Encrypted result (decoded): " << decoded_result[0] << setprecision(10) << endl;
        cout << "Expected result: " << expected << endl;
        cout << "Difference: " << (decoded_result[0] - expected) << endl; // 차이 출력(오차)
    }
}

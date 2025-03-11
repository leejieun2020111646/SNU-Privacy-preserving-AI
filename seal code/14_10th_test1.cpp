#include "examples.h"

using namespace std;
using namespace seal;

void evaluate_polynomial()
{
    print_example_banner("Example: CKKS Basics (4th Degree Polynomial)");

    // CKKS 파라미터 설정
    size_t poly_modulus_degree = 16384;
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    // 총 200비트의 coeff_modulus (60, 40, 40, 60) 사용
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 40, 60 }));

    // 초기 스케일을 2^40로 설정
    double scale = pow(2.0, 40);

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    // 키 생성: 비밀키, 공개키, relinearization 및 Galois 키 생성
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // CKKS 인코더 생성 및 슬롯 개수 확인
    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    // [0,1] 구간의 점들을 입력 벡터로 구성
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

    cout << "Evaluating polynomial PI*x^4 + 0.4*x^2 + 1 ..." << endl;

    Plaintext plain_coeff_pi, plain_coeff_04, plain_coeff1;
    encoder.encode(3.14159265, scale, plain_coeff_pi);
    encoder.encode(0.4, scale, plain_coeff_04);
    encoder.encode(1.0, scale, plain_coeff1);

    Plaintext x_plain;
    print_line(__LINE__);
    cout << "Encode input vector." << endl;
    encoder.encode(input, scale, x_plain);
    Ciphertext x_encrypted;
    encryptor.encrypt(x_plain, x_encrypted);

    Ciphertext x2_encrypted;
    print_line(__LINE__);
    cout << "Compute x^2 and relinearize:" << endl;
    evaluator.square(x_encrypted, x2_encrypted);
    evaluator.relinearize_inplace(x2_encrypted, relin_keys);
    cout << "    + Scale of x^2 before rescale: " << log2(x2_encrypted.scale()) << " bits" << endl;

    print_line(__LINE__);
    cout << "Rescale x^2." << endl;
    evaluator.rescale_to_next_inplace(x2_encrypted);
    cout << "    + Scale of x^2 after rescale: " << log2(x2_encrypted.scale()) << " bits" << endl;

    Ciphertext x4_encrypted;
    print_line(__LINE__);
    cout << "Compute (x^2)^2 = x^4 and relinearize:" << endl;
    evaluator.square(x2_encrypted, x4_encrypted);
    evaluator.relinearize_inplace(x4_encrypted, relin_keys);
    cout << "    + Scale of x^4 before rescale: " << log2(x4_encrypted.scale()) << " bits" << endl;

    // rescale: x4_encrypted의 스케일 조정
    print_line(__LINE__);
    cout << "Rescale x^4." << endl;
    evaluator.rescale_to_next_inplace(x4_encrypted);
    //추가
    cout << "    + Scale of x^4 after rescale: " << log2(x4_encrypted.scale()) << " bits" << endl;

    // 항1: PI * x^4
    print_line(__LINE__);
    cout << "LOG TEST1" << endl;
    cout << "Compute and rescale PI * x^4." << endl;
    cout << "LOG TEST2" << endl;
    Ciphertext term1;
    cout << "LOG TEST3" << endl;
    //+
    evaluator.mod_switch_to_inplace(plain_coeff_pi, x4_encrypted.parms_id());
    evaluator.multiply_plain(x4_encrypted, plain_coeff_pi, term1);
    cout << "    + Scale of PI*x^4 before rescale: " << log2(term1.scale()) << " bits" << endl;
    evaluator.rescale_to_next_inplace(term1);
    cout << "    + Scale of PI*x^4 after rescale: " << log2(term1.scale()) << " bits" << endl;
    cout << "[parms_id] 항1: PI * x^4 plain_coeff_pi : "
         << context.get_context_data(plain_coeff_pi.parms_id())->chain_index() << endl;
    cout << "[parms_id] 항1: PI * x^4 x4_encrypted : " << context.get_context_data(x4_encrypted.parms_id())->chain_index() << endl;
    // 항2: 0.4 * x^2
    print_line(__LINE__);
    cout << "Compute and rescale 0.4 * x^2." << endl;
    Ciphertext term2;
    evaluator.mod_switch_to_inplace(plain_coeff_04, x2_encrypted.parms_id());
    evaluator.multiply_plain(x2_encrypted, plain_coeff_04, term2);
    cout << "    + Scale of 0.4*x^2 before rescale: " << log2(term2.scale()) << " bits" << endl;
    evaluator.rescale_to_next_inplace(term2);
    cout << "    + Scale of 0.4*x^2 after rescale: " << log2(term2.scale()) << " bits" << endl;

    print_line(__LINE__);
    cout << "Normalize scales and encryption parameters." << endl;
    term1.scale() = pow(2.0, 40);
    term2.scale() = pow(2.0, 40);
    plain_coeff1.scale() = pow(2.0, 40);

    parms_id_type last_parms_id = term1.parms_id();
    evaluator.mod_switch_to_inplace(term2, last_parms_id);
    evaluator.mod_switch_to_inplace(plain_coeff1, last_parms_id);

    print_line(__LINE__);
    cout << "Compute PI*x^4 + 0.4*x^2 + 1." << endl;
    Ciphertext encrypted_result;
    evaluator.add(term1, term2, encrypted_result);
    evaluator.add_plain_inplace(encrypted_result, plain_coeff1);

    Plaintext plain_result;
    print_line(__LINE__);
    cout << "Decrypt and decode PI*x^4 + 0.4*x^2 + 1." << endl;
    cout << "    + Expected result:" << endl;
    vector<double> true_result;
    for (size_t i = 0; i < input.size(); i++)
    {
        double x = input[i];
        // 계산: PI*x^4 + 0.4*x^2 + 1
        true_result.push_back(3.14159265 * x * x * x * x + 0.4 * x * x + 1);
    }
    print_vector(true_result, 3, 7);
    cout << "LOG TEST" << endl;

    /*
    암호문을 복호화하고 결과를 디코딩하여 출력
    */
    decryptor.decrypt(encrypted_result, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);
    cout << "    + Computed result .." << endl;
    print_vector(result, 3, 7);
}

#include "examples.h"

using namespace std;
using namespace seal;

void evaluate_polynomial_17()
{
    print_example_banner("Example: CKKS Polynomial Evaluation");

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

    vector<double> input(slot_count);
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++)
    {
        input[i] = i * step_size;
    }
    cout << "Input vector: " << endl;
    print_vector(input, 3, 7);

    int degree;
    cout << "몇 차 다항식을 평가하겠습니까? ";
    cin >> degree;

    vector<Plaintext> plain_coeffs(degree + 1);
    vector<double> user_inputs(degree + 1);

    for (int i = 0; i <= degree; i++)
    {
        cout << "Enter coefficient for x^" << i << ": ";
        cin >> user_inputs[i];
        encoder.encode(vector<double>(slot_count, user_inputs[i]), scale, plain_coeffs[i]);
    }

    cout << "Coefficients encoded successfully." << endl;

    Plaintext x_plain;
    encoder.encode(input, scale, x_plain);
    Ciphertext x_encrypted;
    encryptor.encrypt(x_plain, x_encrypted);
    cout << "x encrypted successfully." << endl;

    vector<Ciphertext> x_powers(degree + 1);
    Plaintext one_plain;
    encoder.encode(vector<double>(slot_count, 1.0), scale, one_plain);
    encryptor.encrypt(one_plain, x_powers[0]);
    x_powers[1] = x_encrypted;

    for (int i = 2; i <= degree; i++)
    {
        evaluator.multiply(x_powers[i - 1], x_encrypted, x_powers[i]);
        evaluator.relinearize_inplace(x_powers[i], relin_keys);
        evaluator.rescale_to_next_inplace(x_powers[i]);
    }

    for (int i = 0; i <= degree; i++)
    {
        evaluator.mod_switch_to_inplace(plain_coeffs[i], x_powers[degree].parms_id());
    }

    Ciphertext encrypted_result;
    encryptor.encrypt(plain_coeffs[0], encrypted_result);

    for (int i = 1; i <= degree; i++)
    {
        Ciphertext term;
        evaluator.multiply_plain(x_powers[i], plain_coeffs[i], term);
        evaluator.add_inplace(encrypted_result, term);
    }

    cout << "Polynomial evaluation completed." << endl;

    Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);

    cout << "Computed result:" << endl;
    print_vector(result, 3, 7);
}

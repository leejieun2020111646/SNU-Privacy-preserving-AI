// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

int main()
{
    cout << "Microsoft SEAL version: " << SEAL_VERSION << endl;
    while (true)
    {
        cout << "+---------------------------------------------------------+" << endl;
        cout << "| The following examples should be executed while reading |" << endl;
        cout << "| comments in associated files in native/examples/.       |" << endl;
        cout << "+---------------------------------------------------------+" << endl;
        cout << "| Examples                   | Source Files               |" << endl;
        cout << "+----------------------------+----------------------------+" << endl;
        cout << "| 1. BFV Basics              | 1_bfv_basics.cpp           |" << endl;
        cout << "| 2. Encoders                | 2_encoders.cpp             |" << endl;
        cout << "| 3. Levels                  | 3_levels.cpp               |" << endl;
        cout << "| 4. BGV Basics              | 4_bgv_basics.cpp           |" << endl;
        cout << "| 5. CKKS Basics             | 5_ckks_basics.cpp          |" << endl;
        cout << "| 6. Rotation                | 6_rotation.cpp             |" << endl;
        cout << "| 7. Serialization           | 7_serialization.cpp        |" << endl;
        cout << "| 8. Performance Test        | 8_performance.cpp          |" << endl;
        cout << "| 9. Vector x Matrix 3x3     | 9_multiply_vector_3.cpp    |" << endl;
        cout << "| 10.Vector x Matrix 4x4     | 10_multiply_vector_4.cpp   |" << endl;
        cout << "| 11.Vector x Matrix nxn     | 11_multiply_vector_n.cpp   |" << endl;
        cout << "| 12.Matrix x Matrix nxn     | 12_multiply_matrix_n.cpp   |" << endl;
        cout << "| 13. test 25.01.10.         | 13_test.cpp                |" << endl;
        cout << "| 14. 10차다항식 01.13.      | 14_test1.cpp               |" << endl;
        cout << "| 15. 4차다항식 01.17.       | 15_TEST_4th.cpp            |" << endl;
        cout << "| 16. 10차다항식 01.20.      | 16_TEST_10th.cpp           |" << endl;
        cout << "| 17. 17코드.                | 17_test.cpp                |" << endl;
        cout << "| 18. 18코드.                | 18_test.cpp                |" << endl;
        cout << "| 19. 19코드.                | 19_test.cpp                |" << endl;
        cout << "+----------------------------+----------------------------+" << endl;

        /*
        Print how much memory we have allocated from the current memory pool.
        By default the memory pool will be a static global pool and the
        MemoryManager class can be used to change it. Most users should have
        little or no reason to touch the memory allocation system.
        */
        size_t megabytes = MemoryManager::GetPool().alloc_byte_count() >> 20;
        cout << "[" << setw(7) << right << megabytes << " MB] "
             << "Total allocation from the memory pool" << endl;

        int selection = 0;
        bool valid = true;
        do
        {
            cout << endl << "> Run example (1 ~ 20) or exit (0): ";
            if (!(cin >> selection))
            {
                valid = false;
            }
            else if (selection < 0 || selection > 25)
            {
                valid = false;
            }
            else
            {
                valid = true;
            }
            if (!valid)
            {
                cout << "  [Beep~~] valid option: type 0 ~ 20" << endl;
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
            }
        } while (!valid);

        switch (selection)
        {
        case 1:
            example_bfv_basics();
            break;

        case 2:
            example_encoders();
            break;

        case 3:
            example_levels();
            break;

        case 4:
            example_bgv_basics();
            break;

        case 5:
            example_ckks_basics();
            break;

        case 6:
            example_rotation();
            break;

        case 7:
            example_serialization();
            break;

        case 8:
            example_performance_test();
            break;

        case 9:
            example_multiply_vector_matrix_3();
            break;

        case 10:
            example_multiply_vector_matrix_4();
            break;

        case 11:
            example_multiply_vector_matrix_dynamic();
            break;

        case 12:
            example_multiply_matrix_matrix_dynamic();
            break;

        case 13:
            example_to_test();
            break;

        case 14:
            evaluate_polynomial();
            break;

        case 15:
            evaluate_polynomial_4th();
            break;
        case 16:
            evaluate_polynomial_10th();
            break;
        case 17:
            evaluate_polynomial_17();
            break;
        case 18:
            evaluate_polynomial_18();
            break;
        case 19:
            evaluate_polynomial_19();
            break;

        case 0:
            return 0;
        }
    }

    return 0;
}

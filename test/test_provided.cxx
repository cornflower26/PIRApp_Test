#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest/doctest.h"
#include "../include-shared/logger.hpp"
#include "../include/drivers/hypercube_driver.hpp"
#include "../include/pkg/agent.hpp"

#include "../include-shared/constants.hpp"
#include "../include-shared/util.hpp"
#include "../include/drivers/repl_driver.hpp"
#include "../src/drivers/repl_driver.cxx"
#include "../include/pkg/cloud.hpp"
#include "pkg/benchmark.hpp"

TEST_CASE("sample") { CHECK(true); }

/**
TEST_CASE("Identity Matrix prod vector") {
    boost::numeric::ublas::matrix<double> M (2,2);
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
            if (i == j) M(i,j) = 1;
            else M(i,j) = 0;
        }
    }
    MatrixPrint(M);
    boost::numeric::ublas::vector<double> y (2,0);
    y[0] = 1;
    VectorPrint(y);
    VectorPrint(boost::numeric::ublas::prod(M,y));
    CHECK(true);
}

TEST_CASE("Small Matrix prod vector") {
    boost::numeric::ublas::matrix<double> M (2,2);
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
            if (i != j) M(i,j) = 1;
            else M(i,j) = 0;
        }
    }
    MatrixPrint(M);
    boost::numeric::ublas::vector<double> y (2,0);
    y[0] = 1;
    VectorPrint(y);
    VectorPrint(boost::numeric::ublas::prod(M,y));
    CHECK(true);
}

TEST_CASE("Identity Matrix solve") {
    boost::numeric::ublas::matrix<double> M (2,2);
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
            if (i == j) M(i,j) = 1;
            else M(i,j) = 0;
        }
    }
    MatrixPrint(M);
    boost::numeric::ublas::vector<double> y (2,1);
    VectorPrint(y);
    VectorPrint(boost::numeric::ublas::solve(M,y, boost::numeric::ublas::lower_tag()));
    CHECK(true);
}

TEST_CASE("Small Matrix solve") {
    boost::numeric::ublas::matrix<double> M (2,2);
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
            if (i == j) M(i,j) = 2;
            else M(i,j) = 1;
        }
    }
    boost::numeric::ublas::lu_factorize(M);
    MatrixPrint(M);
    boost::numeric::ublas::vector<double> y (2,1);
    VectorPrint(y);
    VectorPrint(boost::numeric::ublas::solve(M,y, boost::numeric::ublas::lower_tag()));
    CHECK(true);
}

TEST_CASE("Medium Matrix prod vector") {
    boost::numeric::ublas::matrix<double> M (9,9);
    for (int i = 0; i < 9; i++) {
        for (int j = 0; j < 9; j++) {
            M(i,j) = (i+j)%2;
        }
    }
    MatrixPrint(M);
    boost::numeric::ublas::vector<double> y (9,1);
    VectorPrint(y);
    VectorPrint(boost::numeric::ublas::prod(M,y));
    CHECK(true);
}

TEST_CASE("Medium Matrix solve") {
    boost::numeric::ublas::matrix<double> M (9,9);
    for (int i = 0; i < 9; i++) {
        for (int j = 0; j < 9; j++) {
            if (i == j) M(i,j) = 1;
            else M(i,j) = 0;
        }
    }
    MatrixPrint(M);
    boost::numeric::ublas::vector<double> y (9,1);
    VectorPrint(y);
    boost::numeric::ublas::lu_factorize(M);
    VectorPrint(boost::numeric::ublas::solve(M,y, boost::numeric::ublas::lower_tag()));
    CHECK(true);
}**/

TEST_CASE("The big one"){
    NTL::ZZ_p::init(NTL::ZZ(199));
    NTL::mat_ZZ_p M;
    M.SetDims(9,9);
    NTL::vec_ZZ_p y;
    y.SetLength(9);
    NTL::ZZ_p determinant( 0);

    CryptoPP::SecByteBlock hash_key_1;
    int tries = 0;
    while (determinant == 0){
        hash_key_1 = SipHash_generate_key();
        for (int i = 0; i < M.NumCols(); i++) {
            std::vector<int> rvector = RandVector(hash_key_1, "value-" +std::to_string(i),9);
            //std::vector<int> rvector = RandIndexVector(hash_key_1, "value-" +std::to_string(i),9);
            for (int j = 0; j < rvector.size(); j++) {
                M[i][j] = NTL::to_ZZ_p(long(rvector[j]));
            }
        }
        determinant = NTL::determinant(M);
        tries++;
    }
    std::cout << M << std::endl;

    std::cout << "Final number of tries: " << tries << ", and the final determinant: " << determinant << std::endl;

    for (int i = 0; i < y.length(); i++) {
        y[i] = NTL::to_ZZ_p(i);
    }

    std::cout << y << std::endl;
    std::cout << "Matrix dim " << M.NumRows() << " by " << M.NumCols() << " and vector dim " << y.length() << std::endl;
    NTL::vec_ZZ_p sol;
    sol.SetLength(y.length());
    NTL::solve(determinant, M,sol,y);

    std::cout << sol << std::endl;
    std::vector<int> x(9);
    //std::cout << "Solution: [";
    for (long i = 0; i < 9; ++i) {
        NTL::ZZ temp = NTL::rep(sol[i]);
        x[i] = to_int(temp);
        //std::cout << sol[i] << " ";
    }
    //std::cout << "]" << std::endl;

    NTL::ZZ_p sol2;
    std::vector<int> rvector = RandVector(hash_key_1, "value-" +std::to_string(5),9);
    for (int i = 0; i < y.length(); i++) {y[i] = NTL::to_ZZ_p(rvector[i]);}
    std::cout << "Solution of " << y << " times " << sol << std::endl;
    NTL::InnerProduct(sol2,y,sol);
    std::cout << sol2 << std::endl;
    CHECK(true);
}


/**
TEST_CASE("The big one"){
    boost::numeric::ublas::matrix<double> M (9,9);
    boost::numeric::ublas::vector<double> y (9,0);
    double determinant = 0;

    int tries = 0;
    while (determinant == 0){
        CryptoPP::SecByteBlock hash_key_1 = SipHash_generate_key();
        std::cout << "Matrix: " << std::endl;
        for (int i = 0; i < M.size1(); i++) {
            std::vector<int> rvector = RandIndexVector(hash_key_1, "value-" +std::to_string(i),9);
            std::cout << "[ ";
            for (int j = 0; j < rvector.size(); j++) {
                M(i,j) = rvector[j];
                std::cout << M(i,j) << " ";
            }
            std::cout << "]" << std::endl;
        }
        determinant = Determinant(M);
        tries++;
    }
    std::cout << "Final number of tries: " << tries << ", and the final determinant: " << determinant << std::endl;
    MatrixPrint(M);
    //std::cout << "[ ";
    for (int i = 0; i < y.size(); i++) {
        y[i] = i;
        //std::cout << y[i] << "," << "value-"+std::to_string(i) << " ";
    }
    //std::cout << "]" << std::endl;
    VectorPrint(y);

    std::vector<int> solve = LinearSolve(M,y);
    std::cout << "Final [ ";
    for (int i =0;i<solve.size();i++) {
        std::cout << solve[i] << " ";
    }
    std::cout << "]" << std::endl;
    CHECK(true);
}

TEST_CASE("createAgent") {
    // Create client object and run
    AgentClient agent = AgentClient("localhost",8080,2,3);
    CHECK(true);
}

TEST_CASE("createCloud") {
    CloudClient cloud = CloudClient(2,3);
    CHECK(true);
}

TEST_CASE("createBenchmark") {
    BenchmarkClient client = BenchmarkClient(2,3);
    CHECK(true);
}

TEST_CASE("getBenchmark0") {
    BenchmarkClient client = BenchmarkClient(2,3);
    int result = client.get(0);
    CHECK(result == 1);
}

TEST_CASE("getBenchmark1") {
    BenchmarkClient client = BenchmarkClient(2,3);
    int result = client.get(1);
    CHECK(result == 1);
}

TEST_CASE("getBenchmark2") {
    BenchmarkClient client = BenchmarkClient(2,3);
    int result = client.get(2);
    CHECK(result == 1);
}

TEST_CASE("getBenchmark3") {
    BenchmarkClient client = BenchmarkClient(2,3);
    int result = client.get(3);
    CHECK(result == 1);
}

TEST_CASE("getBenchmark4") {
    BenchmarkClient client = BenchmarkClient(2,3);
    int result = client.get(4);
    CHECK(result == 1);
}

TEST_CASE("getBenchmark5") {
    BenchmarkClient client = BenchmarkClient(2,3);
    int result = client.get(5);
    CHECK(result == 1);
}

TEST_CASE("getBenchmark6") {
    BenchmarkClient client = BenchmarkClient(2,3);
    int result = client.get(6);
    CHECK(result == 1);
}

TEST_CASE("getBenchmark7") {
    BenchmarkClient client = BenchmarkClient(2,3);
    int result = client.get(7);
    CHECK(result == 1);
}

TEST_CASE("getBenchmark8") {
    BenchmarkClient client = BenchmarkClient(2,3);
    int result = client.get(8);
    CHECK(result == 1);
}
**/


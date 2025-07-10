#pragma once

#include "seal/seal.h"

#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/dsa.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>


#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/hypercube_driver.hpp"


class BenchmarkClient {
public:
    BenchmarkClient(int d, int s);
    int get(int index);

    void insert(int index, int val);
    void cube(std::vector<int>& cube);
    void cube(std::string filename);

private:
    int dimension, sidelength;
    std::shared_ptr<HypercubeDriver> hypercube_driver;
};
//
// Created by TJANUSZEWICZ on 09/07/2025.
//
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>
#include <chrono>

#include "../../include-shared/logger.hpp"
#include "../../include/drivers/hypercube_driver.hpp"
#include "../../include/pkg/benchmark.hpp"

double averageRetrievalTime(int d, int s, int iter, int idx) {
    using clock = std::chrono::high_resolution_clock;
    using nanoseconds = std::chrono::nanoseconds;

    BenchmarkClient client = BenchmarkClient(d,s);
    long long totalNanoseconds = 0;
    int result = 0;  // This variable stores the addition result

    //std::cout << std::endl;
    // Run the addition iter times
    for (int i = 0; i < iter; ++i) {
        auto start = clock::now();
        result = client.get(idx);    // Perform the addition
        auto end = clock::now();

        // Calculate the duration in nanoseconds
        auto duration = std::chrono::duration_cast<nanoseconds>(end - start).count();
        //std::cout << duration << " ";
        totalNanoseconds += duration;
    }
    //std::cout << totalNanoseconds << std::endl;

    // Compute and return the average time per addition in nanoseconds.
    return static_cast<double>(totalNanoseconds) / double(iter);
}

/*
 * Usage: ./pir_agent_single
 */
int main(int argc, char *argv[]) {
    // Initialize logger
    initLogger();

    /**
    // Parse args
    if (argc != 5) {
        std::cout << "Usage: ./pir_agent <address> <port> <dimension> <sidelength>"
                  << std::endl;
        return 1;
    }
    int d = std::stoi(argv[1]);
    int s = std::stoi(argv[2]);
    int iters = std::stoi(argv[3]);
    int index = std::stoi(argv[4]);
    **/

    int iters = 10;
    int index = 0;

    for (int d = 1; d < 3; d++) {
        for (int s = 1; s < 100; s++) {
            std::cout << "Timing for side length " << s << " and dimension "<< d << " " << averageRetrievalTime(d, s, iters, index) << std::endl;
        }
    }
    return 0;
}



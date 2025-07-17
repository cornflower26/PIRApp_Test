#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>

#include "../../include-shared/logger.hpp"
#include "../../include/pkg/key_cloud.hpp"

/*
 * Usage: ./keyword_pir_cloud
 */
int main(int argc, char *argv[]) {
    // Initialize logger
    initLogger();

    // Parse args
    if (!(argc == 5)) {
        std::cout << "Usage: ./keyword_pir_cloud <port> <dimension> <sidelength> <epsilon>"
                  << std::endl;
        return 1;
    }
    int port = std::stoi(argv[1]);
    int d = std::stoi(argv[2]);
    int s = std::stoi(argv[3]);
    int epsilon = std::stoi(argv[4]);

    // Create a cloud object and run.
    KeyCloudClient cloud = KeyCloudClient(d, s,epsilon);
    cloud.run(port);
    return 0;
}
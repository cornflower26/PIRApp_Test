#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>

#include "../../include-shared/logger.hpp"
#include "../../include/drivers/hypercube_driver.hpp"
#include "../../include/pkg/key_agent.hpp"

/*
 * Usage: ./keyword_pir_agent
 */
int main(int argc, char *argv[]) {
    // Initialize logger
    initLogger();

    // Parse args
    if (argc != 6) {
        std::cout << "Usage: ./keyword_pir_agent <address> <port> <dimension> <sidelength>"
                  << std::endl;
        return 1;
    }
    std::string address = argv[1];
    int port = std::stoi(argv[2]);
    int d = std::stoi(argv[3]);
    int s = std::stoi(argv[4]);
    int epsilon = std::stoi(argv[5]);

    // Create client object and run
    KeyAgentClient agent = KeyAgentClient(address, port, d, s,epsilon);
    agent.run();
    return 0;
}

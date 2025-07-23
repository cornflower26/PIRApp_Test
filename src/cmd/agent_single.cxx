#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>

#include "../../include-shared/logger.hpp"
#include "../../include/drivers/hypercube_driver.hpp"
#include "../../include/pkg/agent.hpp"

/*
 * Usage: ./pir_agent_single
 */
int main(int argc, char *argv[]) {
    // Initialize logger
    initLogger();

    // Parse args
    if (argc != 6) {
        std::cout << "Usage: ./pir_agent <address> <port> <dimension> <sidelength>"
                  << std::endl;
        return 1;
    }
    std::string address = argv[1];
    int port = std::stoi(argv[2]);
    int d = std::stoi(argv[3]);
    int s = std::stoi(argv[4]);

    std::string command = "get ";
    command += argv[5];
    // Create client object and perform a single get
    AgentClient agent = AgentClient(address, port, d, s);
    agent.HandleRetrieve(command);
    //agent.run();
    return 0;
}

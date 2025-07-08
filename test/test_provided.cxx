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

TEST_CASE("sample") { CHECK(true); }

TEST_CASE("createAgent") {
    // Create client object and run
    AgentClient agent = AgentClient("localhost",8080,2,3);
    CHECK(true);
}

TEST_CASE("createCloud") {
    CloudClient cloud = CloudClient(2,3);
    CHECK(true);
}


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



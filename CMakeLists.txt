cmake_minimum_required(VERSION 3.28.0)

# project details
project(PIRApp VERSION 1.0)
set(CLOUD_EXEC_NAME pir_cloud)
set(AGENT_EXEC_NAME pir_agent)
set(AGENT_SINGLE_EXEC_NAME pir_agent_single)
set(BENCHMARK_EXEC_NAME pir_benchmark)
set(LIBRARY_NAME pir_app_lib)
set(LIBRARY_NAME_SHARED pir_app_lib_shared)
set(LIBRARY_NAME_TA pir_app_lib_ta)
set(CMAKE_CXX_SCAN_FOR_MODULES 0)
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -I/usr/lib/clang/17/include")

# packages
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
include(Boost)
# include(Cryptopp)
include(CTest)
include(Doctest)
include(Documentation)
include(Warnings)
include(Curses)
include(Sqlite3)
include(SEAL)

# add shared libraries
set(SOURCES_SHARED
  src-shared/messages.cxx
  src-shared/logger.cxx
  src-shared/util.cxx)
add_library(${LIBRARY_NAME_SHARED} ${SOURCES_SHARED})
target_include_directories(${LIBRARY_NAME_SHARED} PUBLIC ${PROJECT_SOURCE_DIR}/include-shared)
target_include_directories(${LIBRARY_NAME_SHARED} PUBLIC "/usr/local/include/SEAL-4.1")
target_link_libraries(${LIBRARY_NAME_SHARED} PUBLIC doctest)
target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE cryptopp)
# target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE cryptopp-shared)
target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE sqlite3)
target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE SEAL::seal)
target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE ${Boost_LIBRARIES})
target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE ${CURSES_LIBRARIES})

# add student libraries
set(SOURCES
  src/pkg/cloud.cxx
  src/pkg/agent.cxx
  src/drivers/cli_driver.cxx
  src/drivers/crypto_driver.cxx
  src/drivers/network_driver.cxx
  src/drivers/repl_driver.cxx
  src/drivers/hypercube_driver.cxx
  src/pkg/benchmark.cxx
        include/pkg/key_agent.hpp
        include/pkg/key_cloud.hpp)
add_library(${LIBRARY_NAME} ${SOURCES})
target_include_directories(${LIBRARY_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include-shared ${PROJECT_SOURCE_DIR}/include)
target_include_directories(${LIBRARY_NAME} PUBLIC "/usr/local/include/SEAL-4.1")
target_link_libraries(${LIBRARY_NAME} PRIVATE ${LIBRARY_NAME_SHARED})


# add cloud executables
add_executable(${CLOUD_EXEC_NAME} src/cmd/cloud.cxx)
target_link_libraries(${CLOUD_EXEC_NAME} PRIVATE ${LIBRARY_NAME})


# add agent executables
add_executable(${AGENT_EXEC_NAME} src/cmd/agent.cxx
        src/cmd/key_agent.cxx
        src/cmd/key_cloud.cxx)
target_link_libraries(${AGENT_EXEC_NAME} PRIVATE ${LIBRARY_NAME})

add_executable(${AGENT_SINGLE_EXEC_NAME} src/cmd/agent_single.cxx)
target_link_libraries(${AGENT_SINGLE_EXEC_NAME} PRIVATE ${LIBRARY_NAME})

add_executable(${BENCHMARK_EXEC_NAME} src/cmd/benchmark.cxx)
target_link_libraries(${BENCHMARK_EXEC_NAME} PRIVATE ${LIBRARY_NAME})


# properties
set_target_properties(
  ${LIBRARY_NAME}
  ${CLOUD_EXEC_NAME}
  ${AGENT_EXEC_NAME}
  ${AGENT_SINGLE_EXEC_NAME}
  ${BENCHMARK_EXEC_NAME}
    PROPERTIES
      CXX_STANDARD 20
      CXX_STANDARD_REQUIRED YES
      CXX_EXTENSIONS YES
)

# ta properties
if ( "$ENV{CS1515_TA_MODE}" STREQUAL "on" )
  set_target_properties(
    ${LIBRARY_NAME_TA}
        PROPERTIES
          CXX_STANDARD 20
          CXX_STANDARD_REQUIRED YES
          CXX_EXTENSIONS YES
  )
endif()

# add tests
add_subdirectory(test)
add_custom_target(check ./test.sh)
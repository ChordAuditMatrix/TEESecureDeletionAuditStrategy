cmake_minimum_required(VERSION 3.16)
project(TEESecureDeletion VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(CheckCXXSourceCompiles)

# ==================== Options ====================
option(CAM_BUILD_BENCHMARK "Build benchmarks" OFF)
option(CAM_BUILD_TESTS "Build tests" OFF)
option(CAM_GENERATE_DOCS "Generate Doxygen documentation" OFF)

# ==================== CoreLib Dependency ====================
# Keep this plugin's test switch from enabling CoreLib's own test suite.
set(TEE_SECURE_DELETION_BUILD_TESTS ${CAM_BUILD_TESTS})
set(CAM_BUILD_TESTS OFF)
add_subdirectory(3rdparty/CoreLib EXCLUDE_FROM_ALL)
set(CAM_BUILD_TESTS ${TEE_SECURE_DELETION_BUILD_TESTS})

# ==================== Sanitizer ====================
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_REQUIRED_FLAGS "-fsanitize=address -fno-omit-frame-pointer")

    check_cxx_source_compiles("
        #include <stdlib.h>
        int main() {
            volatile int *p = (int*)malloc(sizeof(int));
            *p = 42;
            free((void*)p);
            return 0;
        }
    " HAS_ASAN)

    if(HAS_ASAN)
        message(STATUS "Sanitizer enabled for Debug build")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
        set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} -fsanitize=address")
    else()
        message(STATUS "Sanitizer not supported (compiler or linker)")
    endif()
endif()

# ==================== Windows Export ====================
if(CMAKE_C_COMPILER_ID MATCHES "MSVC")
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

# ==================== Strategy Shared Library ====================
set(SOURCE
  source/strategy.cpp
)

add_library(${PROJECT_NAME} SHARED ${SOURCE})
target_link_libraries(${PROJECT_NAME} PRIVATE ChordAuditMatrixLib)
target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(CAM_BUILD_TESTS)
    enable_testing()
    add_executable(TEESecureDeletionAuditStrategyTests
        tests/tee_secure_deletion_strategy_tests.cpp)
    target_link_libraries(TEESecureDeletionAuditStrategyTests
        PRIVATE ${PROJECT_NAME} ChordAuditMatrixLib)
    add_test(NAME TEESecureDeletionAuditStrategyTests
        COMMAND TEESecureDeletionAuditStrategyTests)
    add_executable(TEESecureDeletionExperiment
        tests/assured_deletion_experiment.cpp)
    target_link_libraries(TEESecureDeletionExperiment
        PRIVATE ${PROJECT_NAME} ChordAuditMatrixLib)
endif()

set_target_properties(${PROJECT_NAME} PROPERTIES
    PREFIX ""
    VERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

# ==================== Doxygen ====================
if(CAM_GENERATE_DOCS)
    find_package(Doxygen QUIET)
    if(DOXYGEN_FOUND)
        set(DOXYGEN_PROJECT_NAME ${PROJECT_NAME})
        set(DOXYGEN_PROJECT_BRIEF "Audit strategy module")
        set(DOXYGEN_OUTPUT_LANGUAGE "English")
        set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/.cmake/Doxyfile.in)
        set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
        configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
        add_custom_target(${PROJECT_NAME}-docs ALL
            COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Generating API documentation with Doxygen"
            VERBATIM)
    else()
        message(WARNING "Doxygen not found; skipping ${PROJECT_NAME}-docs target. Install Doxygen or configure with -DCAM_GENERATE_DOCS=OFF.")
    endif()
endif()

cmake_minimum_required(VERSION 3.10)

# project details
project(SignalApp VERSION 1.0)
set(EXEC_NAME signal_app)
set(LIBRARY_NAME signal_app_lib)
set(LIBRARY_NAME_SHARED signal_app_lib_shared)
set(LIBRARY_NAME_TA signal_app_lib_ta)

# packages
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
include(Boost)
# include(Cryptopp)
include(CTest)
include(Doctest)
include(Documentation)
include(Warnings)
include(Curses)

# add shared libraries
set(SOURCES_SHARED src-shared/messages.cxx src-shared/logger.cxx src-shared/util.cxx)
add_library(${LIBRARY_NAME_SHARED} ${SOURCES_SHARED})
target_include_directories(${LIBRARY_NAME_SHARED} PUBLIC ${PROJECT_SOURCE_DIR}/include-shared)
target_link_libraries(${LIBRARY_NAME_SHARED} PUBLIC doctest)
target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE cryptopp)
# target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE cryptopp-shared)
target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE ${Boost_LIBRARIES})
target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE ${CURSES_LIBRARIES})

# add student libraries
set(SOURCES
  src/pkg/client.cxx
  src/drivers/crypto_driver.cxx
  src/drivers/network_driver.cxx
  src/drivers/cli_driver.cxx)
add_library(${LIBRARY_NAME} ${SOURCES})
target_include_directories(${LIBRARY_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include-shared ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(${LIBRARY_NAME} PRIVATE ${LIBRARY_NAME_SHARED})

# add ta libraries
if ( "$ENV{CS1515_TA_MODE}" STREQUAL "on" )
  set(SOURCES_TA
    src-ta/pkg/client.cxx
    src-ta/drivers/crypto_driver.cxx
    src-ta/drivers/network_driver.cxx
    src-ta/drivers/cli_driver.cxx)
  add_library(${LIBRARY_NAME_TA} ${SOURCES_TA})
  target_include_directories(${LIBRARY_NAME_TA} PUBLIC ${PROJECT_SOURCE_DIR}/include-shared ${PROJECT_SOURCE_DIR}/include-ta)
  target_link_libraries(${LIBRARY_NAME_TA} PRIVATE ${LIBRARY_NAME_SHARED})
endif()

# add executables
if ( "$ENV{CS1515_TA_MODE}" STREQUAL "on" )
  add_executable(${EXEC_NAME} src-ta/cmd/main.cxx)
  target_link_libraries(${EXEC_NAME} PRIVATE ${LIBRARY_NAME_TA})
else()
  add_executable(${EXEC_NAME} src/cmd/main.cxx)
  target_link_libraries(${EXEC_NAME} PRIVATE ${LIBRARY_NAME})
endif()

# properties
set_target_properties(
  ${LIBRARY_NAME} ${LIBRARY_NAME_SHARED} ${EXEC_NAME}
    PROPERTIES
      CXX_STANDARD 17
      CXX_STANDARD_REQUIRED YES
      CXX_EXTENSIONS NO
)

# ta properties
if ( "$ENV{CS1515_TA_MODE}" STREQUAL "on" )
  set_target_properties(
    ${LIBRARY_NAME_TA}
        PROPERTIES
          CXX_STANDARD 17
          CXX_STANDARD_REQUIRED YES
          CXX_EXTENSIONS NO
  )
endif()

# add tests
add_subdirectory(test)
add_custom_target(check ./test.sh)

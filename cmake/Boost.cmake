find_package(Boost 1.71 REQUIRED COMPONENTS thread system filesystem log)
include_directories( ${Boost_INCLUDE_DIR} )
add_definitions(-DBOOST_LOG_DYN_LINK)

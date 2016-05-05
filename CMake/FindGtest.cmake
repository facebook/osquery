INCLUDE_DIRECTORIES("${CMAKE_SOURCE_DIR}/third-party/gmock-1.7.0/gtest/include" "${CMAKE_SOURCE_DIR}/third-party/gmock-1.7.0/include")
if(WIN32)
    SET(BUILD_SHARED_LIBS ON CACHE BOOL "Build shared gtest library" FORCE)
endif()
ADD_SUBDIRECTORY("${CMAKE_SOURCE_DIR}/third-party/gmock-1.7.0")

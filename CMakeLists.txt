CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(liboauth-dev)

SET(CPACK_PACKAGE_CONTACT "Patrick Charrier <patrick.charrier@gmail.com>")
INCLUDE(CPack)

# use packages
SET(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
#FIND_PACKAGE(Boost COMPONENTS thread date_time REQUIRED)
FIND_PACKAGE(MsIntTypes COMPONENTS REQUIRED)
FIND_PACKAGE(OpenSSL COMPONENTS REQUIRED)

# setup directories
SET (CMAKE_LIBRARY_OUTPUT_DIRECTORY
   ${PROJECT_BINARY_DIR}/bin
   CACHE PATH
   "Single Directory for all Libraries"
   )
SET (CMAKE_RUNTIME_OUTPUT_DIRECTORY
   ${PROJECT_BINARY_DIR}/bin
   CACHE PATH
   "Single Directory for all Executables."
   )
SET (CMAKE_ARCHIVE_OUTPUT_DIRECTORY
   ${PROJECT_BINARY_DIR}/lib
   CACHE PATH
   "Single Directory for all static libraries."
   )

# settings
SET(CMAKE_BUILD_TYPE Release)
INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR})
#LINK_DIRECTORIES(${Boost_LIBRARY_DIRS} ${OGRE_LIB_DIR})

# build subdirectories
ADD_SUBDIRECTORY(src)

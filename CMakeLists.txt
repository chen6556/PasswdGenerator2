cmake_minimum_required(VERSION 3.20.0)
project(PasswdGenerator2 VERSION 0.0.1)

include(CTest)
enable_testing()

if (MSVC)
    add_compile_options("/utf-8")
    add_compile_options("/arch:AVX2")
    add_compile_options("/MP")
endif()

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/output/)

find_package(Qt6 REQUIRED COMPONENTS Widgets Gui Core)

find_package(OpenSSL REQUIRED)

add_subdirectory(src)
include_directories(inc)

qt_add_executable(PasswdGenerator2
    MANUAL_FINALIZATION
    src/main.cpp
    inc/MainWindow.hpp

    ${_SOURCES}
    res/icon.rc
    res/Icons.qrc
)

target_link_libraries(PasswdGenerator2 PRIVATE Qt6::Widgets Qt6::Gui Qt6::Core OpenSSL::SSL OpenSSL::Crypto)

set_target_properties(PasswdGenerator2 PROPERTIES
    MACOSX_BUNDLE_GUI_IDENTIFIER my.example.com
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

qt_finalize_executable(PasswdGenerator2)
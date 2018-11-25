cmake_minimum_required(VERSION 3.9)
project(debugger)
add_subdirectory(deps/command_prompt)
set(CMAKE_CXX_COMPILER clang++-6.0)
set(CMAKE_CXX_STANDARD 17)
set(EXECUTABLE_OUTPUT_PATH ../build/bin)

set(SOURCES main.cpp src/Debugger.cpp src/Debugger.h src/Breakpoint.cpp src/Breakpoint.h src/utils.h src/Symbol.cpp src/Symbol.h)
set(CMDPROMPT_LIB deps/command_prompt/src/cmdprompt/CommandPrompt.cpp deps/command_prompt/src/cmdprompt/CommandPrompt.h)
add_library(command_prompt STATIC ${CMDPROMPT_LIB})
add_executable(debugger ${SOURCES})
add_executable(debugee ./tests/debugee.cpp)
set_target_properties(debugee PROPERTIES COMPILE_FLAGS "-g -O0 -std=c++17 -Wall")

add_custom_target(
        libelfin
        COMMAND make
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/deps/libelfin
)
target_link_libraries(debugger
        command_prompt
        ${PROJECT_SOURCE_DIR}/deps/libelfin/dwarf/libdwarf++.so
        ${PROJECT_SOURCE_DIR}/deps/libelfin/elf/libelf++.so)

add_dependencies(debugger libelfin)
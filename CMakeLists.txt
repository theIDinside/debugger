cmake_minimum_required(VERSION 3.15)
project(debugger)
add_subdirectory(deps/command_prompt)
set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_CXX_STANDARD 17)
set(EXECUTABLE_OUTPUT_PATH ../build/bin)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

string(ASCII 27 ESC)
set(Blue "${ESC}[34m")
set(Red "${ESC}[31m")
set(Cyan "${ESC}[36m")
set(Green "${ESC}[38;5;46m")
set(RedImportant "${ESC}[31;5;1m")
set(CyanImportan "${ESC}[36;5;1m")
set(Header "${ESC}[32;1m")
set(Stop "${ESC}[39m")

set(RUNS_FROM_BASH true)

function(color_msg arg1 arg2)
    set(Text ${arg1})
    set(ColorCmd ${arg2})
    message("${ColorCmd}${Text}${Stop}")
endfunction()

set(SOURCES main.cpp src/Debugger.cpp src/Debugger.h src/Breakpoint.cpp src/Breakpoint.h src/Symbol.cpp src/Symbol.h src/utils.h)
set(CMDPROMPT_LIB deps/command_prompt/src/cmdprompt/CommandPrompt.cpp deps/command_prompt/src/cmdprompt/CommandPrompt.h)
add_library(command_prompt STATIC ${CMDPROMPT_LIB})

add_executable(debugger ${SOURCES})

# we compile our test debuggee here.
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

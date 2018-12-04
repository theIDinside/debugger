cmake_minimum_required(VERSION 3.9)
project(debugger)
add_subdirectory(deps/command_prompt)
set(CMAKE_CXX_COMPILER clang++-6.0)
set(CMAKE_CXX_STANDARD 17)
set(EXECUTABLE_OUTPUT_PATH ../build/bin)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(HEAVYCPP ${PROJECT_SOURCE_DIR}/src/heavy_cpp.h.gch)
set(HEAVYC ${PROJECT_SOURCE_DIR}/src/heavy_c.h.gch)

# uses the PrecompiledHeader macro, that can be found here: https://github.com/larsch/cmake-precompiled-header
include(PrecompiledHeader.cmake)

message(${HEAVYCPP})
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

if($ENV{COLORTERM} STREQUAL "truecolor" AND ${RUNS_FROM_BASH})
        message("Terminal environment variables found.")
    if(EXISTS ${HEAVYCPP})
        color_msg("Heavy cpp include, precompiled header file exists [${HEAVYCPP}]" ${Green})
    else()
        color_msg("Heavy cpp include, precompiled header file doesn't exists: [${HEAVYCPP}]" "${RedImportant}")
    endif()

    if(EXISTS ${HEAVYC})
        color_msg("Heavy c include, precompiled header file exists [${HEAVYC}]" ${Green})
    else()
        color_msg("Heavy c include, precompiled header file doesn't exists [${HEAVYC}]" "${RedImportant}")
    endif()
endif()


set(SOURCES main.cpp src/Debugger.cpp src/Debugger.h src/Breakpoint.cpp src/Breakpoint.h src/Symbol.cpp src/Symbol.h src/utils.h)
set(HEAVY ${HEAVYCPP} ${HEAVYC})
set(CMDPROMPT_LIB deps/command_prompt/src/cmdprompt/CommandPrompt.cpp deps/command_prompt/src/cmdprompt/CommandPrompt.h)
add_library(command_prompt STATIC ${CMDPROMPT_LIB})

add_executable(debugger ${SOURCES})
add_precompiled_header(debugger src/heavy_cpp.h SOURCE_CXX src/heavy_cpp.cpp FORCEINCLUDE)
add_precompiled_header(debugger src/heavy_c.h SOURCE_CXX src/heavy_c.cpp FORCEINCLUDE)

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
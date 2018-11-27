#include <iostream>
#include <unistd.h>
#include <string>
#include "src/Debugger.h"
#include <vector>

enum Process: int {
    Child = 0,
    Parent = 1
};


int main(int argc, char** argv) {
    
    if(argc != 2) {
        std::cerr << "\r\nYou need to provide tracee in order to start debugging." << std::endl;
    } else if(argc >= 2) {
        auto pid = fork();
        if(pid == Process::Child) {
            auto prog = argv[1];
            if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {

                std::cerr << "Error in ptrace\n";
            }
            execl(prog, prog, nullptr);
        } else if(pid >= Process::Parent) {
            Debugger dbg{argv[1], pid};
            dbg.load_program(dbg.m_program_name.value_or(argv[1]));
            dbg.run();
        }
    }
    return 0;
}
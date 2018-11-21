#include <iostream>
#include <unistd.h>
#include <string>
#include "src/Debugger.h"

enum Process: int {
    Child = 0,
    Parent = 1
};


int main(int argc, char** argv) {
    if(argc != 2) {
        std::cerr << "You need to provide tracee in order to start debugging.";
        exit(1);
    } else {
        Debugger dbg{};
        if(auto pid = fork(); pid == Process::Child) {

        } else if(pid == Process::Parent) {
            dbg.load_program(argv[1]);
            dbg.set_pid(pid);
            dbg.run();
        }
    }
    return 0;
}
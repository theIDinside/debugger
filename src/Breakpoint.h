//
// Created by cx on 2018-11-18.
//

#ifndef DEBUGGER_BREAKPOINT_H
#define DEBUGGER_BREAKPOINT_H


#include <wait.h>
#include <sys/ptrace.h>
#include <cstdint>

class Breakpoint {
public:
    using InstructionAddress = std::intptr_t;


    Breakpoint() = delete;
    Breakpoint(pid_t pid, InstructionAddress address);
    Breakpoint(const Breakpoint&);
    Breakpoint(Breakpoint&&) noexcept;
    Breakpoint& operator=(const Breakpoint& bp);
    ~Breakpoint();

    void enable();
    void disable();

    auto is_enabled() -> bool;
    auto get_address() -> InstructionAddress;
private:
    pid_t m_pid;
    InstructionAddress m_addr;
    bool m_enabled;
    std::uint8_t m_saved_data;
};


#endif //DEBUGGER_BREAKPOINT_H

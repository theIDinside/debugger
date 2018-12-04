//
// Created by cx on 2018-11-18.
//

#ifndef DEBUGGER_BREAKPOINT_H
#define DEBUGGER_BREAKPOINT_H


#include <wait.h>
#include <sys/ptrace.h>
#include <cstdint>
#include <iostream>
#include <iomanip>

#ifndef SWAP_IN_INTERRUPT
    #define SWAP_IN_INTERRUPT(x) static_cast<uint64_t>((x & ~0xff) | 0xcc)
#endif



constexpr uint64_t SWAP_IN_INTERRUPT_INSTRUCTION(uint64_t data) {
    return ((data & ~0xff) | 0xcc);
}

constexpr uint64_t RESTORE_DATA(uint64_t data, uint8_t saved_data) {
    return ((data & ~0xff) | saved_data);
}

enum BreakType {
    Permanent,
    Temporary
};

class Breakpoint {
public:
    using InstructionAddress = std::intptr_t;


    Breakpoint() = default;
    Breakpoint(pid_t pid, InstructionAddress address, BreakType breakpoint_type=BreakType::Permanent);
    Breakpoint(const Breakpoint&);
    Breakpoint(Breakpoint&&) noexcept;
    Breakpoint& operator=(const Breakpoint& bp);
    virtual ~Breakpoint();

    void enable();
    void disable();

    auto is_enabled() -> bool;
    auto get_address() -> InstructionAddress;
protected:
    pid_t m_pid;
    InstructionAddress m_addr;
    bool m_enabled;
    std::uint8_t m_saved_data;
    BreakType m_breakpoint_type;
};

class StepToBreakpoint : public Breakpoint {
public:
    StepToBreakpoint(pid_t pid, InstructionAddress address) : Breakpoint(pid, address, Temporary) {

    }
    ~StepToBreakpoint() override {
        if(is_enabled()){
            disable();
            std::cout << "disabling 0x" << std::setfill('0') << std::setw(16) << std::hex << m_addr << '\r' << std::endl;
        }
    }
};



#endif //DEBUGGER_BREAKPOINT_H


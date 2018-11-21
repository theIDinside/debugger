//
// Created by cx on 2018-11-18.
//

#include <utility>
#include "Breakpoint.h"

Breakpoint::Breakpoint(pid_t pid, Breakpoint::InstructionAddress address) : m_pid(pid), m_addr(address),m_enabled{false}, m_saved_data{} {

}

Breakpoint::~Breakpoint() {

}

Breakpoint::Breakpoint(const Breakpoint &bp) : m_pid(bp.m_pid), m_addr(bp.m_addr), m_enabled{bp.m_enabled}, m_saved_data{bp.m_saved_data} {

}

void Breakpoint::enable() {
    auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr);
    m_saved_data = static_cast<uint8_t>(data & 0xff); // the original data/instruction at address, saved so we can put it back later
    uint64_t int3 = 0xcc; // interrupt vector, which tells the cpu to interrupt this sys call
    uint64_t data_and_int3 = ((data & ~0xff) | int3);
    // lets replace the data at address, with our interrupt instruction, that passes control to to the breakpoint interrupt handler
    ptrace(PTRACE_POKEDATA, m_pid, m_addr, data_and_int3);
    this->m_enabled = true;
}

void Breakpoint::disable() {
    auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr);
    auto restored_data = ((data & ~0xff) | m_saved_data);
    ptrace(PTRACE_POKEDATA, m_pid, m_addr, restored_data);
    this->m_enabled = false;
}
auto Breakpoint::is_enabled() -> bool { return m_enabled; }

auto Breakpoint::get_address() -> Breakpoint::InstructionAddress {
    return m_addr;
}

Breakpoint &Breakpoint::operator=(const Breakpoint &bp) {
    this->m_enabled = bp.m_enabled;
    this->m_saved_data = bp.m_saved_data;
    this->m_pid = bp.m_pid;
    this->m_addr = bp.m_addr;
    return *this;
}

Breakpoint::Breakpoint(Breakpoint&& bp) noexcept : m_pid(bp.m_pid), m_addr(bp.m_addr), m_enabled{bp.m_enabled}, m_saved_data{bp.m_saved_data} {

}

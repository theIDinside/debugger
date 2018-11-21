//
// Created by cx on 2018-11-18.
//
#pragma once

#include <cstdint>
#include <utility>
#include <string_view>
#include <string>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <zconf.h>
#include <map>
#include <list>
#include <set>
#include <vector>
#include "Breakpoint.h"
#include "../deps/command_prompt/src/cmdprompt/CommandPrompt.h"
#include <array>

enum CommandParameterAmt: int {
    ONE = 1,
    TWO = 2,
    THREE = 3,
    ARBITRARY // so if we type break 0xffffaaaa 0xabcd1234 0x0223aacc 0x11110202 ... 0x11114fff, it will add breakpoints to everyone in the list that is a valid address
};

enum class reg {
    rax, rbx, rcx, rdx,
    rdi, rsi, rbp, rsp,
    r8,  r9,  r10, r11,
    r12, r13, r14, r15,
    rip, rflags,    cs,
    orig_rax, fs_base,
    gs_base,
    fs, gs, ss, ds, es
};

constexpr std::size_t n_registers = 27;

struct reg_descriptor {
    reg r;
    int dwarf_reg;
    std::string name;
};

class Debugger {
public:
    const static std::array<reg_descriptor, n_registers> g_register_descriptors;
    using String = std::string;
    using InstructionAddr = std::intptr_t;
    using usize = std::size_t;
    std::map<std::string, CommandParameterAmt> command_variations; // a command name -> a set of variations, either 1, 2... how many arguments
    Debugger();
    Debugger(const String& program, pid_t pid);
    ~Debugger();
    void run();

    void set_pid(pid_t pid);
    void setup_command_prompt();
    /*
     * --- Callable commands from the prompt ---
     */
    void load_program(const String& debugee);
    void handle_command(std::string input);
    /* ----------------------------------------*/
    std::optional<String> m_program_name;
private:

    /* register commands    */
    // register IO commands
    void dump_registers();                                              // todo: unimplemented. Dump all registers and their values
    void set_pc(uint64_t pc);                                           // todo: unimplemented. Set program counter to address pc
    uint64_t get_pc();
    void set_register_value(reg r, uint64_t value);                     // todo: unimplemented. Set register r to value
    uint64_t get_register_value(reg r);                                 // todo: unimplemented. Get value in register r
    uint64_t get_register_val_dwarf_index(unsigned register_number);    // todo: unimplemented. Get value in register, using dwarf index
    // register search
    std::string get_register_name(reg r);                               // todo: unimplemented. Get register name, from reg descriptor
    reg get_register_from_name(const std::string& name);                // todo: unimplemented. Get register descriptor from name
    /*-------------------*/

    /* memory IO commands*/
    uint64_t read_memory(uint64_t address);                             // todo: unimplemented. Read word (64 bits) from address
    void write_memory(uint64_t address, uint64_t value);                // todo: unimplemented. Write word (64 bits) to address
    /*-------------------*/

    /*  command debugee commands */
    void wait_for_signal();                                             // todo: unimplemented. Wait for signal from tracee
    void set_breakpoint(InstructionAddr address);
    void continue_execution();
    void stepn(usize n=1);                                              // todo: unimplemented. Step n instructions forward
    void step_over_breakpoint();                                        // todo: unimplemented. Step over breakpoint, if next instruction has one
    /*---------------------------*/

    void listn_source_lines(usize n=10);                                // todo: unimplemented. List n source lines around this instruction address / location in source file

    std::optional<pid_t> m_pid;
    std::map<InstructionAddr, Breakpoint> m_breakpoints;
    std::vector<std::string> m_commands;
    bool setup;
    CommandPrompt cmd;
    bool m_running;
};

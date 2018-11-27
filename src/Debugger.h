//
// Created by cx on 2018-11-18.
//
#pragma once

// c-includes
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <zconf.h>

// standard cpp library
#include <cstdint>
#include <utility>
#include <array>
#include <string_view>
#include <string>
#include <map>
#include <list>
#include <set>
#include <vector>
// my own & 3rd party libs
#include "Breakpoint.h"
#include "../deps/command_prompt/src/cmdprompt/CommandPrompt.h"
#include "../deps/libelfin/dwarf/dwarf++.hh"
#include "../deps/libelfin/elf/elf++.hh"
#include "Symbol.h"

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

struct Block {
    uint64_t base_address;
    std::size_t block_length;
    uint64_t* data;
    Block(uint64_t address, std::size_t block_length) : base_address(address), block_length(block_length), data(new uint64_t[block_length]) {}
    ~Block() {
        delete[] data;
    }
};

class Debugger {
public:
    const static std::array<reg_descriptor, n_registers> g_register_descriptors;
    using String = std::string;
    using InstructionAddr = std::intptr_t;
    using usize = std::size_t;
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
    CommandPrompt cmd;
private:

    /* register commands    */
    // register IO commands
    void dump_registers();
    void set_pc(uint64_t pc);
    uint64_t get_pc();
    void set_register_value(reg r, uint64_t value);
    void set_register_struct(user_regs_struct& rf, reg r, uint64_t value);
    uint64_t get_register_value(reg r);
    uint64_t extract_register_value(user_regs_struct &reg_file, reg r);
    uint64_t get_register_val_dwarf_index(unsigned reg_num);    // todo: unimplemented. Get value in register, using dwarf index
    // rzegister search
    std::string get_register_name(reg r);
    reg get_register_from_name(const std::string& name);
    /*-------------------*/

    /* memory IO commands*/
    auto read_memory(uint64_t address);
    auto read_memory_area(uint64_t address, std::size_t block_length);  // todo: write a function that reads a block of memory, instead of individual quad-words, use

    void write_memory(uint64_t address, uint64_t value);
    void write_block_to_memory(uint64_t address);                       // todo: write a function that writes a block of memory instead of individual quad-words

    void watch_variable(uint64_t address);
    /*-------------------*/
    /*  command debugee commands */
    void wait_for_signal();
    // breakpoint related commands & functions
    void set_breakpoint(InstructionAddr address, bool print=true);
    void set_breakpoint_at_main();
    void set_breakpoint_at_function(const std::string& func);
    void set_breakpoint_at_source_line(const std::string& file_name, unsigned line);

    void remove_breakpoint(std::intptr_t address);

    void single_step_with_breakpoint_check();
    void step_over_breakpoint(bool continue_after=false);
    void step_source_line(usize lines=1);
    void single_step_instruction();
    void continue_execution();
    void stepn(usize n=1);                                              // todo: unimplemented. Step n instructions forward
    void step_in();
    void step_out();
    void step_over();
    /*---------------------------*/
    void listn_source_lines(const std::string& source_file, usize line_num, usize context=5);                                // todo: unimplemented. List n source lines around this instruction address / location in source file
    void debug_print();
    void handle_signal_trap(siginfo_t info);

    dwarf::die get_function_at_pc(uint64_t pc);
    dwarf::die get_die_at_pc(uint64_t pc, dwarf::DW_TAG tag);
    dwarf::line_table::iterator get_line_entry_iterator_at(uint64_t pc);
    std::optional<dwarf::line_table::iterator> get_line_entry_at(uint64_t pc);

    siginfo_t get_signal_info();

    std::optional<pid_t> m_pid;
    std::map<InstructionAddr, Breakpoint> m_breakpoints;
    std::vector<std::string> m_commands;
    bool setup;

    bool m_running;
    bool entered_main_subroutine;
    dwarf::dwarf m_dwarf;
    elf::elf m_elf;

    std::vector<symbols::Symbol> lookup_symbol(const std::string &name);
    std::map<std::string, std::set<symbols::Symbol>> m_symbol_lookup;
};

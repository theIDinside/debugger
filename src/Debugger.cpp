//
// Created by cx on 2018-11-18.
//

#include <iostream>
#include "Debugger.h"
#include <sys/wait.h>
#include "utils.h"
#include <sstream>
#include <sys/user.h>
#include <iomanip>

const std::array<reg_descriptor, n_registers> construct_register_array() {
    return std::array<reg_descriptor, n_registers>{{
                                                           { reg::r15, 15, "r15" },
                                                           { reg::r14, 14, "r14" },
                                                           { reg::r13, 13, "r13" },
                                                           { reg::r12, 12, "r12" },
                                                           { reg::rbp, 6, "rbp" },
                                                           { reg::rbx, 3, "rbx" },
                                                           { reg::r11, 11, "r11" },
                                                           { reg::r10, 10, "r10" },
                                                           { reg::r9, 9, "r9" },
                                                           { reg::r8, 8, "r8" },
                                                           { reg::rax, 0, "rax" },
                                                           { reg::rcx, 2, "rcx" },
                                                           { reg::rdx, 1, "rdx" },
                                                           { reg::rsi, 4, "rsi" },
                                                           { reg::rdi, 5, "rdi" },
                                                           { reg::orig_rax, -1, "orig_rax" },
                                                           { reg::rip, -1, "rip" },
                                                           { reg::cs, 51, "cs" },
                                                           { reg::rflags, 49, "eflags" },
                                                           { reg::rsp, 7, "rsp" },
                                                           { reg::ss, 52, "ss" },
                                                           { reg::fs_base, 58, "fs_base" },
                                                           { reg::gs_base, 59, "gs_base" },
                                                           { reg::ds, 53, "ds" },
                                                           { reg::es, 50, "es" },
                                                           { reg::fs, 54, "fs" },
                                                           { reg::gs, 55, "gs" }
                                                   }};
}
const std::vector<std::string> construct_commands() {
    auto v = std::vector<std::string>{"break", "continue", "step", "stepn", "list", "listn", "load", "quit", "register"};
    std::sort(v.begin(), v.end());
    return v;
}

const std::array<reg_descriptor, n_registers> Debugger::g_register_descriptors = construct_register_array();

Debugger::Debugger() :
    m_program_name{}, m_pid{}, m_breakpoints{}, setup(false),
    m_commands{construct_commands()},
    cmd{"debug> ", false}
{
    setup_command_prompt();
}

void Debugger::load_program(const Debugger::String &debugee) {
    m_program_name = debugee;
}

Debugger::Debugger(const Debugger::String &program, pid_t pid) :
    m_program_name(program), m_pid(pid),
    m_breakpoints{}, setup(true),
    m_commands{construct_commands()},
    cmd{"debug> ", false} {
    setup_command_prompt();
}

void Debugger::set_pid(pid_t pid) {
    this->m_pid = pid;
}

void Debugger::setup_command_prompt() {
    using Strvec = std::vector<std::string>;
    using Result = std::optional<std::string>;
    using String = std::string;
    auto save_history = true;
    /* either put a scope around the CommandPrompt object, or call cmdprompt.disable_rawmode(), to restore terminal.
       Destructor of CommandPrompt calls disable_rawmode(). It's a matter of taste how you do it. */
    cmd.register_validator(std::move([cms = m_commands](auto input) {
        if(input.empty()) return false;
        auto command = strops::split(input)[0];
        return std::any_of(cms.begin(), cms.end(), [&](auto cmd) { return cmd == command; });
    }));
    cmd.register_commands(m_commands);
    // cmd.load_history("./history.log"); // THIS MUST ONLY BE CALLED AFTER A VALIDATOR HAS BEEN REGISTERED, SO THAT NO NON-VALID COMMANDS GET LOADED FROM HISTORY FILE
    cmd.register_completion_cb([cms = m_commands, res=Strvec{}, idx = 0, cur=String{""}, result = Result{}](String str) mutable -> std::optional<std::string> {
        if(cur == str) {
            // continue scrolling through commands
            // using current_index
            if(idx < res.size()) {
                result = res[idx];
                idx++;
                return result;
            } else {
                result = {};
                idx = 0;
                return result;
            }
        } else {
            cur = str;
            idx = 0;
            res.clear();
            // copies all res that begin with str, from cms vector to res vector, so these can be scrolled through.
            auto b = cms.cbegin();
            auto e = cms.cend();
            std::copy_if(b, e, std::back_inserter(res), [&](auto s) { return std::equal(str.begin(), str.end(), s.begin()); });
            if(!res.empty() && idx < res.size()) {
                result = res[idx];
                idx++;
                return result;
            } else {
                idx = 0;
                result = {};
                return result;
            }
        }
    });
}

void Debugger::run() {
    wait_for_signal();
    m_running = true;
    if(setup) {
        while(this->m_running) {
            auto s = cmd.get_input().value_or(std::string{"unknown"});
            handle_command(s);
        }
    } else if(setup && !m_pid.has_value()){
        std::cerr << "Debugee not loaded." << std::endl;
    }
}

void Debugger::handle_command(std::string input) {
    auto args = strops::split(input);
    auto command = args[0];
    if (command == "unknown") {
        cmd.print_error(std::string{"Unknown command"}, cmd.get_error_input().value_or("<couldn't catch erroneous input>"));
    } else if (strops::is_prefix_of(command, "continue")) {
        continue_execution();
    } else if(strops::is_prefix_of(command, "break")) {
        if(args.size() < 2) {
            cmd.print_error(std::string{"You need to provide addresses or line numbers, to the set breakpoint command."});
        } else {
            std::vector<std::string> params{};
            std::copy(args.begin() + 1, args.end(), std::back_inserter(params));
            for (const auto &address : params) {
                if (address.find("0x", 0) == 0) {
                    std::string param{address, 2};
                    set_breakpoint(std::stol(param, nullptr, 16));
                } else {
                    set_breakpoint(std::stol(address, nullptr, 16));
                }
            }
        }
    } else if(command == "list") {
        // todo: call listn_source_lines()
    } else if(command == "listn") {
        // todo: call listn_source_lines(n)
    } else if(command == "step") {
        // todo: call stepn();
    } else if(command == "stepn") {
        // todo: call stepn(n);
    } else if (command == "quit") {
            this->m_running = false;
    } else if(command == "register") {
        if(args.size() < 2) {
            this->cmd.print_error("usage of command: register <read|write|dump> <reg|reg value|>");
        } else {
            std::vector<std::string> params{};
            std::copy(args.begin()+1, args.end(), std::back_inserter(params));
            if(params[0] == "dump") {
                dump_registers();
            } else if(params[0] == "read") {
                // todo: call get_register_value(reg)
            } else if(params[0] == "write") {
                // todo: call set_register_value(reg, value)
            } else {
                this->cmd.print_error("wrong paramater(s) to registers: register ", params[0], "\r\nproper usage of command: register <read|write|dump> <reg|reg value|>");
            }
        };
    } else {
            std::cout << "\r\nErrr???" << std::endl;
    }
}
Debugger::~Debugger() {}
void Debugger::set_breakpoint(InstructionAddr address) {
    std::stringstream ss{""};
    ss << "\r\nSetting breakpoint @ " << std::hex << address;
    cmd.print_data(ss.str());
    Breakpoint bp{m_pid.value(), address};
    bp.enable();
    m_breakpoints.insert({address, bp});
}
void Debugger::continue_execution() {
    ptrace(PTRACE_CONT, m_pid.value(), nullptr, nullptr);
    wait_for_signal();
}
void Debugger::dump_registers() {
    // todo: unimplemented. Dump all registers and their values
    user_regs_struct rf;
    ptrace(PTRACE_GETREGS, m_pid.value(), nullptr, &rf);
    std::cout << "Printing register contents" << std::endl;
    for(const auto& reg : g_register_descriptors) {
        std::cout << '\r' << reg.name << ": " << "0x" << std::setfill('0') << std::setw(16) << std::hex << get_register_value_from_saved(rf, reg.r) << std::endl;
    }
}
uint64_t Debugger::get_register_value_from_saved(user_regs_struct& reg_file, reg r) {
    switch(r) {
        case reg::rax:              return reg_file.rax;
        case reg::rbx:              return reg_file.rbx;
        case reg::rcx:              return reg_file.rcx;
        case reg::rdx:              return reg_file.rdx;
        case reg::rdi:              return reg_file.rdi;
        case reg::rsi:              return reg_file.rsi;
        case reg::rbp:              return reg_file.rbp;
        case reg::rsp:              return reg_file.rsp;
        case reg::r8:               return reg_file.r8;
        case reg::r9:               return reg_file.r9;
        case reg::r10:              return reg_file.r10;
        case reg::r11:              return reg_file.r11;
        case reg::r12:              return reg_file.r12;
        case reg::r13:              return reg_file.r13;
        case reg::r14:              return reg_file.r14;
        case reg::r15:              return reg_file.r15;
        case reg::rip:              return reg_file.rip;
        case reg::rflags:           return reg_file.eflags;
        case reg::cs:               return reg_file.cs;
        case reg::orig_rax:         return reg_file.orig_rax;
        case reg::fs_base:          return reg_file.fs_base;
        case reg::gs_base:          return reg_file.gs_base;
        case reg::fs:               return reg_file.fs;
        case reg::gs:               return reg_file.gs;
        case reg::ss:               return reg_file.ss;
        case reg::ds:               return reg_file.ds;
        case reg::es:               return reg_file.es;
    }
}
uint64_t Debugger::get_register_value(reg r) {
    user_regs_struct reg_file;
    ptrace(PTRACE_GETREGS, m_pid.value(), nullptr, &reg_file); // load register values into user_regs_struct
    switch(r) {
        case reg::rax:              return reg_file.rax;
        case reg::rbx:              return reg_file.rbx;
        case reg::rcx:              return reg_file.rcx;
        case reg::rdx:              return reg_file.rdx;
        case reg::rdi:              return reg_file.rdi;
        case reg::rsi:              return reg_file.rsi;
        case reg::rbp:              return reg_file.rbp;
        case reg::rsp:              return reg_file.rsp;
        case reg::r8:               return reg_file.r8;
        case reg::r9:               return reg_file.r9;
        case reg::r10:              return reg_file.r10;
        case reg::r11:              return reg_file.r11;
        case reg::r12:              return reg_file.r12;
        case reg::r13:              return reg_file.r13;
        case reg::r14:              return reg_file.r14;
        case reg::r15:              return reg_file.r15;
        case reg::rip:              return reg_file.rip;
        case reg::rflags:           return reg_file.eflags;
        case reg::cs:               return reg_file.cs;
        case reg::orig_rax:         return reg_file.orig_rax;
        case reg::fs_base:          return reg_file.fs_base;
        case reg::gs_base:          return reg_file.gs_base;
        case reg::fs:               return reg_file.fs;
        case reg::gs:               return reg_file.gs;
        case reg::ss:               return reg_file.ss;
        case reg::ds:               return reg_file.ds;
        case reg::es:               return reg_file.es;
    }
}
uint64_t Debugger::get_pc() {
    return get_register_value(reg::rip);
}
void Debugger::set_pc(uint64_t pc) {
    set_register_value(reg::rip, pc);
}
void Debugger::set_register_value(reg r, uint64_t value) {
    user_regs_struct rf;
    ptrace(PTRACE_GETREGS, m_pid.value(), nullptr, &rf);
    set_register_struct(rf, r, value);
    ptrace(PTRACE_SETREGS, m_pid.value(), nullptr, &rf);
}
void Debugger::set_register_struct(user_regs_struct &rf, reg r, uint64_t value) {
    switch(r) {
        case reg::rax:      rf.rax = value;        break;
        case reg::rbx:      rf.rbx = value;        break;
        case reg::rcx:      rf.rcx = value;        break;
        case reg::rdx:      rf.rdx = value;        break;
        case reg::rdi:      rf.rdi = value;        break;
        case reg::rsi:      rf.rsi = value;        break;
        case reg::rbp:      rf.rbp = value;        break;
        case reg::rsp:      rf.rsp = value;        break;
        case reg::r8:       rf.r8 = value;         break;
        case reg::r9:       rf.r9 = value;         break;
        case reg::r10:      rf.r10=value;          break;
        case reg::r11:      rf.r11=value;          break;
        case reg::r12:      rf.r12=value;          break;
        case reg::r13:      rf.r13=value;          break;
        case reg::r14:      rf.r14=value;          break;
        case reg::r15:      rf.r15=value;          break;
        case reg::rip:      rf.rip=value;          break;
        case reg::rflags:   rf.eflags=value;       break;
        case reg::cs:       rf.cs=value;           break;
        case reg::orig_rax: rf.orig_rax=value;     break;
        case reg::fs_base:  rf.fs_base=value;      break;
        case reg::gs_base:  rf.gs_base=value;      break;
        case reg::fs:       rf.fs=value;           break;
        case reg::gs:       rf.gs=value;           break;
        case reg::ss:       rf.ss=value;           break;
        case reg::ds:       rf.ds=value;           break;
        case reg::es:       rf.es=value;           break;
    }
}
auto Debugger::read_memory(uint64_t address) {
    return ptrace(PTRACE_PEEKDATA, m_pid.value(), address, nullptr);
}
void Debugger::write_memory(uint64_t address, uint64_t value) {
    ptrace(PTRACE_POKEDATA, m_pid.value(), address, value);
}

void Debugger::step_over_breakpoint() {
    // get program counter, to find out, where we are
    // get breakpoint location in address, which should be where we are - 1
    // this is, because when we hit an instruction, where we have placed int3,
    // execution goes past the breakpoint
    auto pc = get_pc();
    auto breakpoint_address = pc - 1;

    if(m_breakpoints.count(breakpoint_address) > 0) {
        auto& bp = m_breakpoints[breakpoint_address];
        if(bp.is_enabled()) {
            set_pc(breakpoint_address);
            bp.disable();
            ptrace(PTRACE_SINGLESTEP, m_pid.value(), nullptr, nullptr);
            wait_for_signal();
            bp.enable();
        }
    }
}

void Debugger::wait_for_signal() {
    int wait_status;
    auto options = 0;
    waitpid(m_pid.value(), &wait_status, options);
}

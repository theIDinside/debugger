//
// Created by cx on 2018-11-18.
//

#include <iostream>
#include "Debugger.h"
#include "utils.h"
#include <sstream>
#include <string.h>
#include <iomanip>
#include <fstream>
#include <iterator>

#define DEBUG 1
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

static const std::map<std::string, std::string> g_help{
        {"break", "usage: break <address>, sets breakpoint at address"},
        {"bf", "usage: bf <function name>, sets breakpoint at function start, if function can be found."},
        {"continue", "usage: continue, continues execution of tracee"},
        {"quit", "Exits the debugger."},
        {"register", "usage: register <read|write|dump> <reg|reg value|>. <read> reads the value from <reg>, register dump, prints all registers values. <write> <reg value>, writes value to register reg."},
        {"memory", "usage: memory <read|write> <address|address <value>>. Reads value from address, or writes value to address"},
        {"step", "usage: step. Steps 1 step forward."},
        {"stepn", "usage: step <val>. Steps <val> steps forward."},
        {"stepi", "usage: stepi <val>. Steps <val> source lines forward."},
        {"list", "usage: list <val>. List <val> source lines around the instruction, or current address where the tracee is halted."},
        {"symbol", "usage: sy"}
};

const std::vector<std::string> construct_commands() {
    auto v = std::vector<std::string>{"break", "continue", "step", "stepn","stepi", "list", "listn", "load", "quit", "register", "memory", "help", "debug", "bf", "symbol"};
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
    cmd{"debug> ", false}, entered_main_subroutine(false), m_symbol_lookup{}
{
    setup_command_prompt();
    auto fd = open(m_program_name.value().c_str(), O_RDONLY);
    m_elf = elf::elf{elf::create_mmap_loader(fd)};
    m_dwarf = dwarf::dwarf{dwarf::elf::create_loader(m_elf)};
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
    std::cout << "\x1b[39m";
}

void Debugger::run() {
    set_breakpoint_at_main();
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

void Debugger::handle_command(std::string input)
{
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
            for(const auto& param : params) {
                if(param.find(':') != std::string::npos) {
                    auto ps = strops::split(param, ':');
                    auto file = ps[0];
                    try {
                        auto line_no = std::stoi(ps[1], nullptr, 10);
                        set_breakpoint_at_source_line(file, line_no);
                    } catch(std::exception& e) {
                        std::string msg = e.what();
                        cmd.print_error("Exception caught: ", msg);
                    }
                } else {
                    if (param.find("0x", 0) == 0) {
                        std::string address{address, 2};
                        set_breakpoint(std::stol(param, nullptr, 16));
                    } else {
                        set_breakpoint(std::stol(param, nullptr, 16));
                    }
                }
            }
        }
    } else if(command == "list") {
        auto line_iterator = get_line_entry_iterator_at(get_pc());
        listn_source_lines(line_iterator->file->path, line_iterator->line);
    } else if(command == "listn") {
        auto context = args.size() > 1 ? std::stol(args[1]) : 5;
        try{
            auto line_iterator = get_line_entry_iterator_at(get_pc());
            listn_source_lines(line_iterator->file->path, line_iterator->line, context);
        } catch(std::exception& e) {
            std::string msg = e.what();
            cmd.print_error(msg);
        }
    } else if(command == "step") {
        stepn(1);
    } else if(command == "stepn") {
        if(args.size() < 2) {
            cmd.print_error("usage of stepn command: step <value>");
        } else {
            auto steps = std::stoul(args[1]);
            stepn(steps);
        }
    } else if(command == "stepi") {
        step_source_line(1);
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
                try {
                    auto val = get_register_value(get_register_from_name(params[1]));
                    cmd.print_data("Value: ", "0x", std::hex, val);
                } catch(std::exception& e) {
                    std::string msg = e.what();
                    cmd.print_error(std::string{"Exception caught:"}, msg);
                }
            } else if(params[0] == "write") {
                // todo: call set_register_value(reg, value)
            }
        }
    } else if(command == "help") {
        if(args.size() < 2) {
            cmd.print_data("------------------ Command help ------------------");
            cmd.print_data(std::setw(15), std::left, "<Command>", "| ", "<help message>");
            for(const auto& [command, help_txt] : g_help) {
                cmd.print_data(std::setw(15), std::left, command, "| ", help_txt);
            }
            cmd.print_data("--------------------------------------------------");
        } else {
            if(g_help.count(args[1]) > 0) {
                cmd.print_data(g_help.at(args[1]));
            }
        }
    } else if(command == "bf") {
        if(args.size() != 2) {
            cmd.print_error("You need to provide function name to this command!");
        } else {
            auto function_name = args[1];
            set_breakpoint_at_function(function_name);
        }
    } else if(command == "debug") {
        debug_print();
    } else {
            std::cout << "\r\nErrr???" << std::endl;
    }
}

Debugger::~Debugger() {}

void Debugger::continue_execution() {
    step_over_breakpoint();
    ptrace(PTRACE_CONT, m_pid.value(), nullptr, nullptr);
    wait_for_signal();
}
void Debugger::dump_registers() {
    user_regs_struct rf;
    ptrace(PTRACE_GETREGS, m_pid.value(), nullptr, &rf);
    std::cout << "Printing register contents" << std::endl;
    for(const auto& reg : g_register_descriptors) {
        std::cout << '\r' << reg.name << ": " << "0x" << std::setfill('0') << std::setw(16) << std::hex << extract_register_value(
                rf, reg.r) << std::endl;
    }
}
uint64_t Debugger::extract_register_value(user_regs_struct &reg_file, reg r) {
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



void Debugger::wait_for_signal() {
    int wait_status;
    auto options = 0;
    waitpid(m_pid.value(), &wait_status, options);
    auto signal_info = get_signal_info();
    auto process = strops::format("[_]", m_pid.value());
    switch(signal_info.si_signo) {
        case SIGTRAP:
            handle_signal_trap(signal_info);
            break;
        case SIGSEGV:
            cmd.print_data(process, " Segfault: ", signal_info.si_code);
            break;
        default:
            auto signal_caught = strsignal(signal_info.si_signo);
            cmd.print_data(process, " Caught signal: ", signal_caught);
            break;
    }
}

siginfo_t Debugger::get_signal_info() {
    siginfo_t info;
    ptrace(PTRACE_GETSIGINFO, m_pid.value(), nullptr, &info);
    return info;
}

void Debugger::handle_signal_trap(siginfo_t info) {
    switch(info.si_code) {
        case SI_KERNEL: {
            auto msg = std::string{strsignal(info.si_signo)};
            if(msg == "Trace/breakpoint trap") {

            } else {
                auto process = strops::format("[_]", m_pid.value());
                cmd.print_data(process, " ", msg);
                break;
            }
        } case TRAP_BRKPT: {
            set_pc(get_pc() - 1);
            auto process = strops::format("[_]", m_pid.value());
            cmd.print_data(process, " Hit breakpoint at address 0x", std::setfill('0'), std::setw(8), std::hex, get_pc());
            // auto line_iterator = get_line_entry_iterator_at(get_pc());
            // listn_source_lines(line_iterator->file->path, line_iterator->line);
            break;
        } case TRAP_TRACE: {
            // signal caught when single stepping.
            return;
        } default: {
            cmd.print_data("Unknown sigtrap code: ", info.si_code);
            return;
        }
    }
}

reg Debugger::get_register_from_name(const std::string &name) {
    auto cb = g_register_descriptors.cbegin();
    auto ce = g_register_descriptors.cend();
    if(auto res = std::find_if(cb, ce, [&](auto&& reg_desc) { return reg_desc.name == name; }); res == ce) {
        std::string err_msg{"Couldn't find register with name <" + name + ">"};
        throw std::range_error{err_msg};
    } else {
        return res->r;
    }
}

std::string Debugger::get_register_name(reg r) {
    auto cb = g_register_descriptors.cbegin();
    auto ce = g_register_descriptors.cend();
    auto res = std::find_if(cb, ce, [&](auto&& reg_desc) {
        return reg_desc.r == r;
    });
    return res->name;
}



/**
 * Retrieves the function the program is currently in, when the program counter has value pc.
 * @param pc
 * @return dwarf::die
 */
dwarf::die Debugger::get_function_at_pc(uint64_t pc) {
    for(const auto& compilation_unit : m_dwarf.compilation_units())
        if(dwarf::die_pc_range(compilation_unit.root()).contains(pc))
            for(const auto& die : compilation_unit.root())
                if(die.tag == dwarf::DW_TAG::subprogram)
                    if(dwarf::die_pc_range(die).contains(pc)) return die;
    auto msg = strops::format_msg("Could not find function at address _", strops::fmt_val_to_address_str(pc));
    throw std::out_of_range{msg};
}

uint64_t Debugger::get_register_val_dwarf_index(unsigned reg_num) {
    auto cb = g_register_descriptors.cbegin();
    auto ce = g_register_descriptors.cend();
    if(auto it = std::find_if(cb, ce, [=](auto&& rd) { return rd.dwarf_reg == reg_num; }); it == ce)
    {
        auto err_msg = strops::format_msg("Unknown register index _", std::to_string(reg_num));
        throw std::out_of_range{err_msg};
    } else {
        return get_register_value(it->r);
    }
}

dwarf::line_table::iterator Debugger::get_line_entry_iterator_at(uint64_t pc) {
    for(auto& comp_unit : m_dwarf.compilation_units()) {
        if(dwarf::die_pc_range(comp_unit.root()).contains(pc)) {
            auto& lt = comp_unit.get_line_table();
            auto it = lt.find_address(pc);
            if(it == lt.end()) {
                auto v = get_pc();
                auto prog_count = strops::fmt_val_to_address_str(v);
                auto msg = strops::format("PC: _: Line entry not found", v);
                throw std::out_of_range{msg};
            } else {
                return it;
            }
        }
    }
    throw std::out_of_range{"Line entry not found"};
}

void Debugger::listn_source_lines(const std::string &source_file, Debugger::usize line_num, Debugger::usize context) {
    std::ifstream source{source_file};
    std::string line_item;
    auto current_line = 0;

    auto start = (line_num < context) ? 1 : line_num - context;
    auto end = (line_num + context);

    while(current_line < (line_num-context) && (line_num - context > 0)) {
        current_line++;
        auto _temp = std::string{};
        std::getline(source, _temp, '\n');
    }
    while(current_line < (line_num+context+1) && !source.eof()) {
        current_line++;
        std::getline(source, line_item, '\n');
        if(current_line == line_num) {
            auto data = strops::format("\x1b[38;5;112m_>> ", current_line);
            cmd.print_data(data, line_item, "\x1b[39m");
        } else {
            auto data = strops::format("_ : ", current_line);
            cmd.print_data(data, line_item);
        }
    }
    source.close();
}

void Debugger::stepn(Debugger::usize n) {
    step_over_breakpoint();
    for(auto i = 0; i < n; ++i) {
        ptrace(PTRACE_SINGLESTEP, m_pid.value(), nullptr, nullptr);
        wait_for_signal();
    }
}

void Debugger::step_over_breakpoint(bool continue_after) {
    // get program counter, to find out, where we are
    // get breakpoint location in address, which should be where we are - 1
    // this is, because when we hit an instruction, where we have placed int3,
    // execution goes past the breakpoint
    auto pc = get_pc();
    if(m_breakpoints.count(pc) > 0) {
        auto& bp = m_breakpoints[pc];
        if(bp.is_enabled()) {
            bp.disable();
            ptrace(PTRACE_SINGLESTEP, m_pid.value(), nullptr, nullptr);
            wait_for_signal();
            bp.enable();
        }
    }
}

void Debugger::single_step_with_breakpoint_check() {
    if(m_breakpoints.count(get_pc())) {
        step_over_breakpoint();
    } else {
        single_step_instruction();
    }
}

void Debugger::single_step_instruction() {
    ptrace(PTRACE_SINGLESTEP, m_pid.value(), nullptr, nullptr);
    wait_for_signal();
}

void Debugger::step_source_line(Debugger::usize lines) {
    // get current source line
    // while (get_source_line() == current_source_line)
    // keep stepping until false, and we have stepped a single source line.
        single_step_with_breakpoint_check();
        auto value = read_memory(get_pc());
        try {
            auto line_iter = get_line_entry_iterator_at(get_pc());
            auto next_line = line_iter->line+lines;
            single_step_with_breakpoint_check();
            while(line_iter->line < next_line) {
                line_iter = get_line_entry_iterator_at(get_pc());
            }
            listn_source_lines(line_iter->file->path, line_iter->line, 1);
        } catch(std::exception& e) {

        }
}

void Debugger::debug_print() {
    cmd.print_data(strops::fmt_val_to_address_str(m_elf.get_hdr().entry));
    for(const auto& sec : m_elf.sections()) {
        auto name = sec.get_name();
        if(name == ".symtab") {
            for(auto sym : sec.as_symtab()) {
                cmd.print_data(sym.get_name());
                if(sym.get_name() == "main") {
                    auto addr = strops::fmt_val_to_address_str(sym.get_data().value);
                    cmd.print_data("Address: ", addr);
                }
            }
        }
        cmd.print_data(name);
    }
}

void Debugger::set_breakpoint(InstructionAddr address, bool print) {
    std::stringstream ss{""};
    if(print)
        ss << "\r\nSetting breakpoint @ " << std::hex << address;
    cmd.print_data(ss.str());
    Breakpoint bp{m_pid.value(), address};
    bp.enable();
    m_breakpoints.insert({address, bp});
}

/**
 * Sets breakpoint at the first source line of the function func.
 * @param func
 */
void Debugger::set_breakpoint_at_function(const std::string &func) {
    using namespace dwarf;
    using std::pair;
    std::vector<die> function_dies{};
    if(auto lparens = func.find('(', 0); lparens == std::string::npos) {
        for (const auto &cu : m_dwarf.compilation_units()) {
            for (const auto &die : cu.root()) {
                if (die.has(DW_AT::name) && at_name(die) == func) {
                    function_dies.push_back(die);
                    auto low_pc = at_low_pc(die);
                    auto entry_iterator = get_line_entry_iterator_at(low_pc);
                    entry_iterator++; // pass by the prologue of the function
                    set_breakpoint(entry_iterator->address);
                }
            }
        }
    } else {
        // this will be used for, finding functions, specifying parameter lists.
        auto rparens  = func.find(')', lparens);
        auto argument_list = func.substr(lparens+1, rparens-1);
        auto tokens = strops::split(argument_list, ',');
        std::vector<pair<std::string, std::string>> arg_list{};
        for(auto& t : tokens) {
            auto ts = strops::split(t, ' ');
            arg_list.emplace_back(std::forward<pair<std::string, std::string>>(std::make_pair(ts[0], ts[1])));
        }
    }
}

void Debugger::set_breakpoint_at_source_line(const std::string &file_name, unsigned line) {
    for(const auto& cu : m_dwarf.compilation_units()) {
        if(strops::is_suffix_of(file_name, dwarf::at_name(cu.root()))) {
            const auto& lt = cu.get_line_table();
            for(const auto& entry : lt) {
                if(entry.is_stmt && entry.line == line) {
                    set_breakpoint(entry.address);
                }
            }
        }
    }
}

void Debugger::set_breakpoint_at_main() {
    for(const auto& sec : m_elf.sections()) {
        auto name = sec.get_name();
        if(name == ".symtab") {
            for(auto sym : sec.as_symtab()) {
                if(sym.get_name() == "main") {
                    auto addr = strops::fmt_val_to_address_str(sym.get_data().value);
                    cmd.print_data("Set breakpoint at main(): ", addr);
                    set_breakpoint(std::stol(std::string{addr, 2, 16}, 0, 16), false);
                }
            }
        }
    }
}


std::vector<symbols::Symbol> Debugger::lookup_symbol(const std::string &name) {
    std::vector<symbols::Symbol> symbols_found{};
    for(auto& sec : m_elf.sections()) {
        if(sec.get_hdr().type != elf::sht::symtab && sec.get_hdr().type == elf::sht::dynsym) {
            continue; // if we aren't scanning the symbol table and dynamic symbol sections, just skip
        }
        for(auto sym : sec.as_symtab()) {
            if(sym.get_name() == name) {
                auto& data = sym.get_data();
                symbols_found.emplace_back(symbols::Symbol{data.type(), name, data.value});
            }
        }
    }
    return symbols_found;
}

std::optional<dwarf::line_table::iterator> Debugger::get_line_entry_at(uint64_t pc) {
    for(auto& comp_unit : m_dwarf.compilation_units()) {
        if(dwarf::die_pc_range(comp_unit.root()).contains(pc)) {
            auto& lt = comp_unit.get_line_table();
            auto it = lt.find_address(pc);
            if(it == lt.end()) {
                return {};
            } else {
                return {it};
            }
        }
    }
    return {};
}

void Debugger::step_out() {
    auto frame_pointer = get_register_value(reg::rbp);
    auto ret_addr = read_memory(frame_pointer+8);

    auto remove_breakpoint = false;
    if(!m_breakpoints.count(ret_addr)) {
        set_breakpoint(ret_addr);
        remove_breakpoint = true;
    }
    continue_execution();

    if(remove_breakpoint)
        remove_breakpoint(ret_addr);
}

void Debugger::remove_breakpoint(std::intptr_t address) {
    if(m_breakpoints.count(address))
    {
        if(m_breakpoints.at(address).is_enabled())
            m_breakpoints.at(address).disable();
    }
    m_breakpoints.erase(address);
}

void Debugger::step_in() {

}

void Debugger::step_over() {
    auto function_die = get_function_at_pc(get_pc());
    auto start = at_low_pc(function_die);
    auto end = at_high_pc(function_die);

    auto line = get_line_entry_iterator_at(start);
    auto start_line = get_line_entry_iterator_at(get_pc());

    std::vector<StepToBreakpoint> temporary_breakpoits{};
    auto bps = 0;
    while(line->address < end) {
        if(line->address != start_line->address && !m_breakpoints.count(line->address))
        {
            auto addr = static_cast<long>(line->address);
            StepToBreakpoint bp{m_pid.value(), addr};
            bp.enable();
            temporary_breakpoits.emplace_back(std::move(bp));
            bps++;
        }
        ++line;
    }

    auto frame_pointer = get_register_value(reg::rbp);
    auto retaddr = read_memory(frame_pointer+8);

    if(!m_breakpoints.count(retaddr)) {
        temporary_breakpoits.emplace_back(m_pid.value(), retaddr);
        temporary_breakpoits[temporary_breakpoits.size()-1].enable();
    }

    continue_execution();
    // the destructor should handle the disabling all of these breakpoints that has been set.
}

//
// Created by cx on 2018-11-18.
//

#include <iostream>
#include "Debugger.h"
#include <sys/wait.h>
#include "utils.h"
#include <sstream>

Debugger::Debugger() :
    m_program_name{}, m_pid{}, m_breakpoints{}, setup(false),
    m_commands{"break", "continue", "step", "stepn", "list", "listn", "load", "quit"},
    cmd{"debug>", false}
{
    setup_command_prompt();
}



void Debugger::load_program(const Debugger::String &debugee) {
    m_program_name = debugee;
}

Debugger::Debugger(const Debugger::String &program, pid_t pid) :
    m_program_name(program), m_pid(pid),
    m_breakpoints{}, setup(true),
    m_commands{"break", "continue", "step", "stepn", "list", "listn", "load", "quit"},
    cmd{"debug> ", false}  {
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
    int wait_status;
    auto options = 0;
    waitpid(m_pid.value(), &wait_status, options);
    m_running = true;
    if(setup) {
        std::cout << "Enter commands: " << std::endl;
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

    } else if(command == "listn") {

    } else if(command == "step") {

    } else if(command == "stepn") {

    } else if (command == "quit") {
            this->m_running = false;
    } else {
        std::cout << "\r\nErrr???" << std::endl;
    }
}

Debugger::~Debugger() {

}

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
    int wait_status;
    auto options = 0;
    waitpid(m_pid.value(), &wait_status, options);
}

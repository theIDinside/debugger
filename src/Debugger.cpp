//
// Created by cx on 2018-11-18.
//

#include <iostream>
#include "Debugger.h"

Debugger::Debugger() : m_pid{}, m_breakpoints{}, setup(false) {

}

void Debugger::run() {
    if(setup && m_pid.has_value()) {
        while(this->m_running) {
            auto input = cmd->get_input();

        }
    } else {
        std::cerr << "Debugee not loaded." << std::endl;
    }
}

void Debugger::load_program(const Debugger::String &debugee) {
    m_program_name = debugee;
}

Debugger::Debugger(const Debugger::String &program, pid_t pid) : m_program_name(program), m_pid(pid), m_breakpoints{}, setup(true) {

}

void Debugger::set_pid(pid_t pid) {
    this->m_pid = pid;
}

void Debugger::setup_command_prompt(Validator &&validator) {
    cmd = std::make_unique<CommandPrompt>(CommandPrompt{"debug>"});
    auto commands = std::vector<std::string>{"break", "continue", "step", "list"};
    cmd->register_validator([cms = commands](const std::string& in) -> bool {
        return std::any_of(cms.begin(), cms.end(), [&](auto item) { return item == in;});
    });
}

void Debugger::handle_command(const std::string &input) {

}

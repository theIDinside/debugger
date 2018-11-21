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
#include "cmdprompt/CommandPrompt.h"

enum CommandParameterAmt: int {
    ONE = 1,
    TWO = 2,
    THREE = 3,
    ARBITRARY // so if we type break 0xffffaaaa 0xabcd1234 0x0223aacc 0x11110202 ... 0x11114fff, it will add breakpoints to everyone in the list that is a valid address
};


class Debugger {
public:
    using String = std::string;
    using InstructionAddr = std::intptr_t;
    using usize = std::size_t;
    std::map<std::string, CommandParameterAmt> command_variations; // a command name -> a set of variations, either 1, 2... how many arguments
    Debugger();
    Debugger(const String& program, pid_t pid);
    ~Debugger();
    void run();
    void load_program(const String& debugee);
    void set_pid(pid_t pid);
    void setup_command_prompt(Validator&& validator);
    /*
     * --- Callable commands from the prompt ---
     */

    void continue_execution();
    void handle_command(const std::string& input);
    void set_breakpoint();
    std::vector<String> list_source_lines(usize line_no, usize no_lines);
    /* ----------------------------------------*/
private:
    String m_program_name;
    std::optional<pid_t> m_pid;
    std::map<InstructionAddr, Breakpoint> m_breakpoints;
    bool setup;
    std::unique_ptr<CommandPrompt> cmd;
    bool m_running;
};
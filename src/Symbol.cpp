#include <utility>

//
// Created by cx on 2018-11-25.
//

#include "Symbol.h"
#include "utils.h"
#include <cxxabi.h>

std::string symbols::to_string(const symbols::symbol_type& symtype) {
    switch(symtype) {
        case symbol_type::notype:
            return "notype";
        case symbol_type::object:
            return "object";
        case symbol_type::func:
            return "func";
        case symbol_type::section:
            return "section";
        case symbol_type::file:
            return "file";
        default:
            return "notype";
    }
}

symbols::symbol_type symbols::to_symbol_type(elf::stt sym) {
    switch(sym) {
        case elf::stt::object: return symbol_type::object;
        case elf::stt::func: return symbol_type::func;
        case elf::stt::section: return symbol_type::section;
        case elf::stt::file: return symbol_type::file;
        case elf::stt::notype: return symbol_type::notype;
        default: return symbol_type::notype;
    }
}

std::string symbols::to_string(Symbol& sym) {
    auto ret = strops::format_msg("type: _ | name: _ | @[_]",
                       symbols::to_string(sym.m_type),                  // type
                       sym.m_demangled_name.value_or(sym.m_name),       // name
                       strops::fmt_val_to_address_str(sym.m_addr));     // address
    return ret;
}

symbols::Symbol::Symbol(symbols::Symbol::type symtype, std::string name, symbols::Symbol::symbol_address addr) : m_demangled_name{}, m_type(symtype), m_name(
        std::move(name)), m_addr(addr) {
    int stat;
    try {
        auto ptr = abi::__cxa_demangle(m_name.c_str(), nullptr, nullptr, &stat);
        std::string n{ptr};
        this->m_demangled_name = {n};
        free(ptr);
    } catch(...) {
        this->m_demangled_name = {};
    }
}
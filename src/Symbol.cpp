#include <utility>

//
// Created by cx on 2018-11-25.
//

#include "Symbol.h"
#include "utils.h"


std::string symbols::to_string(symbols::SymbolType symtype) {
    switch(symtype) {
        case SymbolType::NoType:
            return "notype";
        case SymbolType::Object:
            return "object";
        case SymbolType::Function:
            return "func";
        case SymbolType::Section:
            return "section";
        case SymbolType::File:
            return "file";
    }
}

symbols::SymbolType symbols::to_symbol_type(elf::stt sym) {
    switch(sym) {
        case elf::stt::object: return SymbolType::Object;
        case elf::stt::func: return SymbolType::Function;
        case elf::stt::section: return SymbolType::Section;
        case elf::stt::file: return SymbolType::File;
        case elf::stt::notype: return SymbolType::NoType;
        default: return SymbolType::NoType;
    }
}

std::string symbols::Symbol::to_string() {
    auto type = symbols::to_string(this->m_type);
    auto addr = strops::format_address(std::to_string(this->m_addr));
    return strops::format_msg("_ _ @[_]", type, m_name, addr);
}

symbols::Symbol::Symbol(symbols::Symbol::type symtype, std::string name, symbols::Symbol::symbol_address addr) : m_type(symtype), m_name(
        std::move(name)), m_addr(addr) {

}

//
// Created by cx on 2018-11-25.
//

#pragma once
#include <string>
#include "../deps/libelfin/elf/elf++.hh"

namespace symbols {

    enum class SymbolType {
        NoType,
        Object,
        Function,
        Section,
        File
    };

    SymbolType to_symbol_type(elf::stt sym);
    std::string to_string(SymbolType symtype);

    struct Symbol {
        using type = SymbolType;
        using symbol_address = uintptr_t;
        Symbol();
        Symbol(type symtype, std::string name, symbol_address addr);
        Symbol(elf::stt symtype, std::string name, symbol_address addr) : Symbol(to_symbol_type(symtype), name, addr) {}
        ~Symbol() = default;
        Symbol(const Symbol& copy) = default;

    protected:
        type m_type;
        std::string m_name;
        std::uintptr_t m_addr;
        std::string to_string();
    };

    struct CppSymbol : public Symbol {
        using type = Symbol::type;
        using sym_addr = Symbol::symbol_address;
        CppSymbol(type symbol_type, std::string name, sym_addr addr) : Symbol(symbol_type, name, addr) {

        }
        ~CppSymbol() = default;
        std::string m_mangled_name;
    };
    CppSymbol from_mangled(std::string name);
};
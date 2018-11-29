#include <utility>

//
// Created by cx on 2018-11-25.
//

#pragma once
#include <string>
#include <optional>
#include "../deps/libelfin/elf/elf++.hh"

namespace symbols {

    enum class symbol_type {
        notype,
        object,
        func,
        section,
        file
    };

    symbol_type to_symbol_type(elf::stt sym);

    struct Symbol {
        using type = symbol_type;
        using symbol_address = uintptr_t;
        Symbol() = default;
        Symbol(type symtype, std::string name, symbol_address addr);
        Symbol(elf::stt symtype, std::string name, symbol_address addr) : Symbol(to_symbol_type(symtype), std::move(name), addr) {}
        Symbol(const Symbol& cp) = default;
        ~Symbol() = default;
        void demangle();
        std::optional<std::string> m_demangled_name{};
        type m_type;
        std::string m_name;
        std::uintptr_t m_addr;
    protected:
    };

    struct CppSymbol : public Symbol {
        using type = Symbol::type;
        using sym_addr = Symbol::symbol_address;
        CppSymbol(type symbol_type, std::string name, sym_addr addr) : Symbol(symbol_type, name, addr) {

        }
        ~CppSymbol() = default;
        std::string m_demangled_name;
    };
    CppSymbol from_mangled(std::string name);


    std::string to_string(symbol_type symtype);
    std::string to_string(Symbol& symbol);
};
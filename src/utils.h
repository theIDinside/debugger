#include <utility>

//
// Created by cx on 2018-11-18.
//
#pragma once
#include <string>
#include <vector>
#include <sstream>
#include <type_traits>
#include <iomanip>

using StrVec = std::vector<std::string>;
using Str = std::string;
namespace strops {
    auto is_prefix_of(const std::string& prefix, const std::string& str) {
        if (prefix.size() > str.size()) return false;
        return std::equal(prefix.cbegin(), prefix.cend(), str.cbegin());
    }

    auto split(const std::string& data, const char delimiter=' ') ->  StrVec {
        auto v = StrVec{};
        std::stringstream ss{data};
        Str item_holder{};
        while(std::getline(ss, item_holder, delimiter)) v.emplace_back(item_holder);
        return v;
    }

    Str format_address(const Str& address) {
        auto pos = address.find_first_of("0x", 0, 2);
        if(pos == std::string::npos) {
            auto s = std::string{};
            s.push_back('0');
            s.push_back('x');
            std::copy(address.cbegin(), address.cend(), std::back_inserter(s));
            return s;
        } else if(pos == 0) {
            return address;
        }
    }

    // this template gets enabled and compiled, via the return type. If the SFINAE thing here, doesn't come out truthy,
    // the return type will simply be "", and therefore not compiled at all. Beautiful.
    template <typename T>
    typename std::enable_if<std::is_arithmetic<T>::value, Str>::type fmt_val_to_address_str(T value) {
        std::stringstream ss{""};
        ss << "0x" << std::setfill('0') << std::setw(16) << std::hex << value;
        return ss.str();
    }

    template <typename ...Args>
    std::string format(const std::string& format_str, Args&&... args) {
        std::stringstream ss{};
        StrVec items = split(format_str, '_');
        auto it = items.cbegin();
        if(items.size()-1 != sizeof...(args))
            throw std::range_error{"Parameter list size not equal to format string place holders"};
        ss << ((*it++ + std::to_string(args)) + ...) << *it;
        return ss.str();
    }

    template <typename ...Args>
    std::string format_msg(const std::string& format_str, Args&&... msgs) {
        std::stringstream ss{};
        StrVec items = split(format_str, '_');
        auto it = items.cbegin();
        if(items.size()-1 != sizeof...(msgs)) {
            throw std::range_error{"Format string not correctly formatted."};
        }
        auto i = 0;
        ss << ((*it++ + msgs) + ...) << *it;
        return ss.str();
    }
};
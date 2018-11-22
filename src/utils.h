#include <utility>

//
// Created by cx on 2018-11-18.
//
#pragma once
#include <string>
#include <vector>
#include <sstream>

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

    template <typename ...Args>
    std::string format(const std::string& format_str, Args&&... args) {
        std::stringstream ss{};
        StrVec items = split(format_str, '_');
        auto it = items.cbegin();
        if(items.size() != sizeof...(args))
            throw std::range_error{"Parameter list size not equal to format string place holders"};
        ss << ((*it++ + std::to_string(args)) + ...) << std::endl;
        return ss.str();
    }
};
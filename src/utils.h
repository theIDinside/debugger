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
        return std::equal(prefix.begin(), prefix.end(), str.begin());
    }

    auto split(std::string data, const char delimiter=' ') ->  StrVec {
        auto v = StrVec{};
        std::stringstream ss{data};
        Str item_holder{};
        while(std::getline(ss, item_holder, delimiter)) v.emplace_back(item_holder);
        return v;
    }

    Str format_address(const Str& address) {
        auto pos = address.find_first_of("0x", 0, 2);
        if(auto s = std::string{""}; pos == std::string::npos) {
            s.push_back('0');
            s.push_back('x');
            std::copy(address.begin(), address.end(), std::back_inserter(s));
            return s;
        } else if(pos == 0) {
            return address;
        }
    }
};
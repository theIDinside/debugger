//
// Created by cx on 2018-11-24.
//

#ifndef DEBUGGER_LINEITERATOR_H
#define DEBUGGER_LINEITERATOR_H
#include <iterator>
#include <fstream>
#include <string>

class LineIterator : public std::istream {
public:
/*
    using value_type = Iterator::value_type;
    using iterator_category = std::input_iterator_tag;
    using difference_type = Iterator::difference_type;
    using pointer = value_type*;
    using reference = value_type&;
*/
    LineIterator(std::fstream& file, const char delimiter='\n') : file{file}, m_line{} {}
    LineIterator(const LineIterator& lit) : file{lit.file}, line_number(lit.line_number), m_line(lit.m_line) {}
    LineIterator(const std::string& file_name, const char delimiter='\n') : file{file_name}, m_line{} {}
    ~LineIterator() { file.close(); }

    std::string operator>>() {
        if(file.eof()) {

        }
            std::getline(file, m_line, '\n');
        return m_line;
    }

    reference operator*() {
        return m_line;
    }

    pointer operator->() {
        return &m_line;
    }

private:
    std::fstream file;
    int line_number;
    std::string m_line;
};


#endif //DEBUGGER_LINEITERATOR_H

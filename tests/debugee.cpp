#include <utility>

//
// Created by cx on 2018-11-21.
//
#include <algorithm>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
struct SimpleStruct {
  explicit SimpleStruct(std::string n) : name(std::move(n)) {}

  ~SimpleStruct() = default;
  void set_name(const char *name) {}
  std::string name;
};

void say_hello() {
  // std::cout << "World says: Hello sir" << std::endl;
  int j = 10 * 24;
  SimpleStruct s{"simon"};
  for (int i = 0; i < 10; i++) {
    int a = 10 * i;
  }
}

void say_goodbye() {
  std::cout << "World says: goodbye sir" << std::endl;
  int p = 203;
}

void simon_says(SimpleStruct &s) { std::cout << s.name << '\n'; }

int main() {

  SimpleStruct s{"simon"};
  say_hello();
  int some_mofo_var = 0;
  some_mofo_var = 10 * 15;
  simon_says(s);
  std::cout << "Hello world" << '\n';
  int b = some_mofo_var - 3;
  auto c = some_mofo_var * b;
  // std::cout << "Goodbye world!" << '\n';
  say_goodbye();
}

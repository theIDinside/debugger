//
// Created by cx on 2018-11-21.
//
#include <iostream>
#include <string>
#include <sstream>
#include <algorithm>

void say_hello() {
	std::cout << "World says: Hello sir" << std::endl;
}

void say_goodbye() {
	std::cout << "World says: goodbye sir" << std::endl;
}

int main() {
    std::cout << "Hello world" << std::endl;
	say_hello();
	int j = 0;
	j = 10*15;
	int b = j-3;
	auto c = j*b;
	std::cout << "Goodbye world!";
	say_goodbye();
}

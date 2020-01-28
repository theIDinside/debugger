#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

int main() {
  std::string s{"mofofofo"};
  std::vector<std::string> v{{"hello"}, {"world"}, {"out there"}};
  std::string world{"world"};
  std::cout << "Was world found? " << std::boolalpha
            << std::any_of(v.begin(), v.end(),
                           [&](auto left) { return left == world; })
            << '\n';
  std::cout << "Characters: " << s << "at pos 2: " << s[2] << std::endl;
  s.replace(2, 3, std::to_string(10));
  std::cout << "After replacing character at 2:" << s << std::endl;
}

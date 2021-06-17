#include <ctime>
#include <iostream>
#include <random>

using namespace std;
  
auto main() -> int {
  mt19937 mt(0);
  for (int i = 0; i < 10; i++) {
      cout << mt() << endl;
  }
  return 0;
}

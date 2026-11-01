#include <iostream>
#include "SiemConsoleApp.hpp"

int main() {
    SiemConsoleApp app("clean_auth.log.txt", "clean_fw.log.txt");
    app.run(std::cin);
    std::cout << "\n=== Final SIEM Session State ===\n" << app << "\n";
    return 0;
}

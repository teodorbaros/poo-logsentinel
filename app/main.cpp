#include <iostream>
#include "SiemConsoleApp.h"

int main() {
    SiemConsoleApp app(std::cout, "sshd", "ufw");
    app.run(std::cin);
    std::cout << app << "\n";
    return 0;
}

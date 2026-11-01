#include <iostream>
#include "SiemConsoleApp.h"

int main() {
    SiemConsoleApp app("sshd_stream", "ufw_stream");
    app.run(std::cin);
    std::cout << "\n=== Final SIEM Session State ===\n" << app << "\n";
    return 0;
}

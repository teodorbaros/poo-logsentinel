#ifndef CONSOLE_BOX_H
#define CONSOLE_BOX_H

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

class ConsoleBox {
private:
    static constexpr std::size_t kInnerWidth = 76;
    static constexpr std::size_t kWrapIndent = 4;

    std::vector<std::string> lines_;
    std::vector<bool> isRule_;  

    void pushLine(const std::string& text) {
        lines_.push_back(text);
        isRule_.push_back(false);
    }

    static std::string rule() { return "+" + std::string(kInnerWidth + 2, '-') + "+"; }

public:
    ConsoleBox& addLine(const std::string& text, std::size_t wrapIndent = kWrapIndent) {
        std::string rest = text;
        while (rest.size() > kInnerWidth) {
            std::size_t cut = rest.rfind(' ', kInnerWidth);
            if (cut == std::string::npos || cut <= wrapIndent) {
                cut = kInnerWidth;
            }
            pushLine(rest.substr(0, cut));
            const std::size_t next = rest.find_first_not_of(' ', cut);
            if (next == std::string::npos) {
                return *this;  
            }
            rest = std::string(wrapIndent, ' ') + rest.substr(next);
        }
        pushLine(rest);
        return *this;
    }

    ConsoleBox& addText(const std::string& text) {
        std::istringstream lines(text);
        std::string line;
        while (std::getline(lines, line)) {
            addLine(line);
        }
        return *this;
    }
    ConsoleBox& addTitle(const std::string& left, const std::string& right) {
        const std::size_t used = left.size() + right.size();
        return addLine(left + std::string(used < kInnerWidth ? kInnerWidth - used : 1, ' ') + right);
    }

    ConsoleBox& addRule() {
        lines_.emplace_back();
        isRule_.push_back(true);
        return *this;
    }

    friend std::ostream& operator<<(std::ostream& os, const ConsoleBox& box) {
        os << rule() << "\n";
        for (std::size_t i = 0; i < box.lines_.size(); i++) {
            if (box.isRule_[i]) {
                os << rule() << "\n";
            } else {
                os << "| " << box.lines_[i] << std::string(kInnerWidth - box.lines_[i].size(), ' ') << " |\n";
            }
        }
        return os << rule() << "\n";
    }
};

#endif

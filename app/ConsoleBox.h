#ifndef CONSOLE_BOX_H
#define CONSOLE_BOX_H

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

// Un chenar de text pentru consola (meniu, rapoarte). Fiecare rand e completat cu spatii pana la aceeasi
// latime, ca marginea din dreapta sa fie dreapta; un rand prea lung e rupt la ultimul spatiu.
// Doar caractere ASCII (+ - |), ca sa arate la fel si in terminalul de Windows.
//
//   +------------------------------+
//   | TITLU                        |
//   +------------------------------+
//   | un rand                      |
//   +------------------------------+
class ConsoleBox {
private:
    static constexpr std::size_t kInnerWidth = 76;
    static constexpr std::size_t kWrapIndent = 4;

    std::vector<std::string> lines_;
    std::vector<bool> isRule_;   // isRule_[i] = randul i e o linie orizontala, nu text

    void pushLine(const std::string& text) {
        lines_.push_back(text);
        isRule_.push_back(false);
    }

    static std::string rule() { return "+" + std::string(kInnerWidth + 2, '-') + "+"; }

public:
    // un rand de text; daca nu incape, se rupe la ultimul spatiu si continua cu `wrapIndent` spatii
    // (de exemplu sub valoarea dintr-un rand "Praguri:   ...")
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
                return *this;   // dupa taietura erau doar spatii
            }
            rest = std::string(wrapIndent, ' ') + rest.substr(next);
        }
        pushLine(rest);
        return *this;
    }

    // mai multe randuri dintr-un text cu '\n' (de exemplu ce afiseaza o alta clasa)
    ConsoleBox& addText(const std::string& text) {
        std::istringstream lines(text);
        std::string line;
        while (std::getline(lines, line)) {
            addLine(line);
        }
        return *this;
    }

    // titlu in stanga, text scurt aliniat la dreapta pe acelasi rand
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

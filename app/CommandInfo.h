#ifndef COMMAND_INFO_H
#define COMMAND_INFO_H

#include <iomanip>
#include <iostream>
#include <string>

class CommandInfo {
private:
    static constexpr int kKeywordWidth = 14;

    int number_;
    std::string keyword_;
    std::string usage_;
    std::string summary_;
    std::string details_;

public:
    CommandInfo(int number, const std::string& keyword, const std::string& usage, const std::string& summary,
                const std::string& details)
        : number_(number), keyword_(keyword), usage_(usage), summary_(summary), details_(details) {}

    bool matches(const std::string& token) const { return token == keyword_ || token == std::to_string(number_); }

    int getNumber() const { return number_; }
    const std::string& getKeyword() const { return keyword_; }

    void printDetails(std::ostream& os) const {
        os << keyword_ << " (sau " << number_ << ") - " << summary_ << "\n\n"
           << "  " << usage_ << "\n\n"
           << details_ << "\n";
    }

    void printUsageError(std::ostream& os) const {
        os << "Comanda incompleta sau gresita. Se scrie: " << usage_ << "\n"
           << "Exemple si detalii: help " << keyword_ << "\n";
    }

    friend std::ostream& operator<<(std::ostream& os, const CommandInfo& cmd) {
        return os << std::setw(2) << cmd.number_ << "  " << std::left << std::setw(kKeywordWidth) << cmd.keyword_
                  << std::right << cmd.summary_;
    }
};

#endif

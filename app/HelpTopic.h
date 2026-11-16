#ifndef HELP_TOPIC_H
#define HELP_TOPIC_H

#include <cctype>
#include <iomanip>
#include <iostream>
#include <string>
class HelpTopic {
private:
    static constexpr int kNameWidth = 14;

    std::string name_;
    std::string summary_;
    std::string text_;

public:
    HelpTopic(const std::string& name, const std::string& summary, const std::string& text)
        : name_(name), summary_(summary), text_(text) {}

    bool matches(const std::string& token) const { return token == name_; }
    void printFull(std::ostream& os) const {
        std::string title = summary_;
        title[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(title[0])));
        os << title << "\n\n" << text_ << "\n";
    }
    friend std::ostream& operator<<(std::ostream& os, const HelpTopic& topic) {
        return os << "help " << std::left << std::setw(kNameWidth) << topic.name_ << std::right << topic.summary_;
    }
};

#endif

#ifndef LOG_SOURCE_HPP
#define LOG_SOURCE_HPP

#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include "LogEntry.hpp"

class LogSource {
private:
    std::string filePath_;
    std::vector<LogEntry> entries_;
    int ignoredLines_;

    void sortChronologically() {
        for (std::size_t i = 0; i < entries_.size(); i++) {
            for (std::size_t j = i + 1; j < entries_.size(); j++) {
                if (entries_[j].isBefore(entries_[i])) {
                    LogEntry temp = entries_[i];
                    entries_[i] = entries_[j];
                    entries_[j] = temp;
                }
            }
        }
    }

public:
    explicit LogSource(const std::string& filePath)
        : filePath_(filePath), ignoredLines_(0) {}

    void ingestFromStream(std::istream& in, int lineCount) {
        std::ofstream outFile(filePath_, std::ios::app);
        for (int i = 0; i < lineCount; i++) {
            std::string month;
            std::string ip;
            int day = 0;
            int hour = 0;
            int minute = 0;
            int second = 0;
            bool failed = false;

            if (in >> month >> day >> hour >> minute >> second >> ip >> failed) {
                if (outFile.is_open()) {
                    outFile << month << " " << day << " " << hour << " "
                            << minute << " " << second << " " << ip << " " << failed << "\n";
                }
                LogEntry entry(month, day, hour, minute, second, ip, failed);
                if (entry.isValid()) {
                    entries_.push_back(entry);
                } else {
                    ignoredLines_++;
                }
            }
        }
        sortChronologically();
    }

    bool loadFromFile() {
        std::ifstream file(filePath_);
        if (!file.is_open()) {
            return false;
        }
        entries_.clear();
        ignoredLines_ = 0;

        std::string month;
        std::string ip;
        int day = 0;
        int hour = 0;
        int minute = 0;
        int second = 0;
        bool failed = false;

        while (file >> month >> day >> hour >> minute >> second >> ip >> failed) {
            LogEntry entry(month, day, hour, minute, second, ip, failed);
            if (entry.isValid()) {
                entries_.push_back(entry);
            } else {
                ignoredLines_++;
            }
        }

        sortChronologically();
        return true;
    }

    std::size_t getEntryCount() const {
        return entries_.size();
    }

    const LogEntry& getEntryAt(std::size_t index) const {
        return entries_[index];
    }

    int printEntriesForIp(std::ostream& os, const std::string& targetIp) const {
        int matched = 0;
        for (std::size_t i = 0; i < entries_.size(); i++) {
            if (entries_[i].matchesIpString(targetIp)) {
                os << "  " << entries_[i] << "\n";
                matched++;
            }
        }
        return matched;
    }

    friend std::ostream& operator<<(std::ostream& os, const LogSource& source) {
        os << "[SSH Source] " << source.filePath_ << ": " << source.entries_.size()
           << " valid entries (" << source.ignoredLines_ << " invalid ignored)";
        return os;
    }
};

#endif // LOG_SOURCE_HPP

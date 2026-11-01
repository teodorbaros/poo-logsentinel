#pragma once

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

    static std::string makeBar(double percent) {
        int filled = static_cast<int>(percent / 5.0);
        std::string bar = "[";
        for (int i = 0; i < 20; i++) {
            if (i < filled) {
                bar = bar + "#";
            } else {
                bar = bar + "-";
            }
        }
        return bar + "]";
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

    void printStatistics(std::ostream& os) const {
        os << "--- SSH Statistics ---\n";
        if (entries_.empty()) {
            os << "  (no data)\n";
            return;
        }

        std::vector<std::string> ips;
        std::vector<int> ipTotal;
        std::vector<int> ipFailed;
        int failed = 0;

        for (std::size_t i = 0; i < entries_.size(); i++) {
            const LogEntry& e = entries_[i];
            if (e.failed_) {
                failed++;
            }
            std::size_t idx = ips.size();
            for (std::size_t j = 0; j < ips.size(); j++) {
                if (ips[j] == e.ip_) {
                    idx = j;
                    break;
                }
            }
            if (idx == ips.size()) {
                ips.push_back(e.ip_);
                ipTotal.push_back(0);
                ipFailed.push_back(0);
            }
            ipTotal[idx]++;
            if (e.failed_) {
                ipFailed[idx]++;
            }
        }

        int total = static_cast<int>(entries_.size());
        int success = total - failed;
        int failPct = static_cast<int>(100.0 * failed / total + 0.5);
        int successPct = 100 - failPct;

        std::size_t worst = 0;
        for (std::size_t j = 1; j < ips.size(); j++) {
            if (ipFailed[j] > ipFailed[worst]) {
                worst = j;
            }
        }

        os << "  Total attempts     : " << total << "\n";
        os << "  Successful logins  : " << success << " (" << successPct << "%) " << makeBar(successPct) << "\n";
        os << "  Failed logins      : " << failed << " (" << failPct << "%) " << makeBar(failPct) << "\n";
        os << "  Distinct source IPs: " << ips.size() << "\n";
        os << "  Avg attempts / IP  : " << (static_cast<int>(10.0 * total / static_cast<double>(ips.size()) + 0.5) / 10.0) << "\n";
        os << "  Most failures from : " << ips[worst] << " (" << ipFailed[worst]
           << " failed out of " << ipTotal[worst] << " attempts)\n";
        os << "  First event        : " << entries_[0] << "\n";
        os << "  Last event         : " << entries_[entries_.size() - 1] << "\n";
        os << "  Observed span      : " << entries_[entries_.size() - 1].secondsSince(entries_[0]) << "s\n";
    }

    friend std::ostream& operator<<(std::ostream& os, const LogSource& source) {
        os << "[SSH Source]\n"
           << "    File            : " << source.filePath_ << "\n"
           << "    Valid entries   : " << source.entries_.size() << "\n"
           << "    Invalid ignored : " << source.ignoredLines_;
        return os;
    }
};

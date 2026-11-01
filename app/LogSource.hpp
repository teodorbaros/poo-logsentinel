#pragma once
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "LogEntry.hpp"
#include "Utils.hpp"

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
            int idx = -1;
            for (std::size_t j = 0; j < ips.size(); j++) {
                if (ips[j] == e.ip_) {
                    idx = static_cast<int>(j);
                    break;
                }
            }
            if (idx < 0) {
                ips.push_back(e.ip_);
                ipTotal.push_back(0);
                ipFailed.push_back(0);
                idx = static_cast<int>(ips.size()) - 1;
            }
            ipTotal[idx]++;
            if (e.failed_) {
                ipFailed[idx]++;
            }
        }

        int total = static_cast<int>(entries_.size());
        int success = total - failed;
        double failRate = 100.0 * failed / total;
        double successRate = 100.0 - failRate;

        int worst = 0;
        for (std::size_t j = 1; j < ips.size(); j++) {
            if (ipFailed[j] > ipFailed[worst]) {
                worst = static_cast<int>(j);
            }
        }

        std::ios::fmtflags oldFlags = os.flags();
        std::streamsize oldPrecision = os.precision();
        os << std::fixed << std::setprecision(1);

        os << "  Total attempts     : " << total << "\n";
        os << "  Successful logins  : " << success << " (" << successRate << "%) " << makeBar(successRate) << "\n";
        os << "  Failed logins      : " << failed << " (" << failRate << "%) " << makeBar(failRate) << "\n";
        os << "  Distinct source IPs: " << ips.size() << "\n";
        os << "  Avg attempts / IP  : " << (1.0 * total / ips.size()) << "\n";
        os << "  Most failures from : " << ips[worst] << " (" << ipFailed[worst]
           << " failed out of " << ipTotal[worst] << " attempts)\n";
        os << "  First event        : " << entries_.front() << "\n";
        os << "  Last event         : " << entries_.back() << "\n";
        os << "  Observed span      : " << entries_.back().secondsSince(entries_.front()) << "s\n";

        os.flags(oldFlags);
        os.precision(oldPrecision);
    }

    friend std::ostream& operator<<(std::ostream& os, const LogSource& source) {
        os << "[SSH Source]\n"
           << "    File            : " << source.filePath_ << "\n"
           << "    Valid entries   : " << source.entries_.size() << "\n"
           << "    Invalid ignored : " << source.ignoredLines_;
        return os;
    }
};


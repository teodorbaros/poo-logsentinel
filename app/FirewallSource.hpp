#ifndef FIREWALL_SOURCE_HPP
#define FIREWALL_SOURCE_HPP

#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include "FirewallEntry.hpp"

class FirewallSource {
private:
    std::string filePath_;
    std::vector<FirewallEntry> entries_;
    int ignoredLines_;

    void sortChronologically() {
        for (std::size_t i = 0; i < entries_.size(); i++) {
            for (std::size_t j = i + 1; j < entries_.size(); j++) {
                if (entries_[j].isBefore(entries_[i])) {
                    FirewallEntry temp = entries_[i];
                    entries_[i] = entries_[j];
                    entries_[j] = temp;
                }
            }
        }
    }

public:
    explicit FirewallSource(const std::string& filePath)
        : filePath_(filePath), ignoredLines_(0) {}

    void ingestFromStream(std::istream& in, int packetCount) {
        std::ofstream outFile(filePath_, std::ios::app);
        for (int i = 0; i < packetCount; i++) {
            std::string month;
            std::string ip;
            std::string proto;
            int day = 0;
            int hour = 0;
            int minute = 0;
            int second = 0;
            int port = 0;
            bool blocked = false;

            if (in >> month >> day >> hour >> minute >> second >> ip >> port >> proto >> blocked) {
                if (outFile.is_open()) {
                    outFile << month << " " << day << " " << hour << " " << minute << " "
                            << second << " " << ip << " " << port << " " << proto << " " << blocked << "\n";
                }
                FirewallEntry entry(month, day, hour, minute, second, ip, port, proto, blocked);
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
        std::string proto;
        int day = 0;
        int hour = 0;
        int minute = 0;
        int second = 0;
        int port = 0;
        bool blocked = false;

        while (file >> month >> day >> hour >> minute >> second >> ip >> port >> proto >> blocked) {
            FirewallEntry entry(month, day, hour, minute, second, ip, port, proto, blocked);
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

    const FirewallEntry& getEntryAt(std::size_t index) const {
        return entries_[index];
    }

    int printPacketsForIp(std::ostream& os, const std::string& targetIp) const {
        int matched = 0;
        for (std::size_t i = 0; i < entries_.size(); i++) {
            if (entries_[i].matchesIpString(targetIp)) {
                os << "  " << entries_[i]
                   << (entries_[i].targetsCriticalService() ? " [CRITICAL-PORT]" : "") << "\n";
                matched++;
            }
        }
        return matched;
    }

    friend std::ostream& operator<<(std::ostream& os, const FirewallSource& source) {
        os << "[FW  Source] " << source.filePath_ << ": " << source.entries_.size()
           << " valid packets (" << source.ignoredLines_ << " invalid ignored)";
        return os;
    }
};

#endif // FIREWALL_SOURCE_HPP

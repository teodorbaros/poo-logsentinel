#ifndef LOG_SOURCE_H
#define LOG_SOURCE_H

#include <algorithm>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <vector>
#include "LogEntry.h"
class LogSource {
private:
    std::string sourceName_;
    std::vector<LogEntry> entries_;
    int ignoredLines_;
    bool readEntry(std::istream& in) {
        std::string month;
        std::string ip;
        int day = 0;
        int hour = 0;
        int minute = 0;
        int second = 0;
        bool failed = false;
        if (in >> month >> day >> hour >> minute >> second >> ip >> failed) {
            const LogEntry entry(month, day, hour, minute, second, ip, failed);
            if (entry.isValid()) {
                entries_.push_back(entry);
                return true;
            }
        }
        ignoredLines_++;
        return false;
    }

public:
    explicit LogSource(const std::string& sourceName) : sourceName_(sourceName), ignoredLines_(0) {}
    int ingestFromStream(std::istream& in, int lineCount) {
        int added = 0;
        for (int i = 0; i < lineCount; i++) {
            added += readEntry(in) ? 1 : 0;
        }
        std::stable_sort(entries_.begin(), entries_.end());   
        return added;
    }
    int ingestUntilEof(std::istream& in) {
        int added = 0;
        std::string line;
        while (std::getline(in, line)) {
            std::istringstream lineStream(line);
            if (!line.empty() && readEntry(lineStream)) {
                added++;
            }
        }
        std::stable_sort(entries_.begin(), entries_.end()); 
        return added;
    }

    int getEntryCount() const { return static_cast<int>(entries_.size()); }
    int getRejectedCount() const { return ignoredLines_; }
    const LogEntry& getEntryAt(int index) const { return entries_[static_cast<std::size_t>(index)]; }
    void printTelemetrySummary(std::ostream& os) const {
        if (entries_.empty()) {
            return;
        }
        std::set<std::string> uniqueIps;
        int fails = 0;
        for (const LogEntry& entry : entries_) {
            uniqueIps.insert(entry.getIpString());
            if (entry.isFailed()) {
                fails++;
            }
        }
        os << "  interval: " << entries_.front().getTimestamp() << " - " << entries_.back().getTimestamp() << "\n"
           << "  " << uniqueIps.size() << " IP-uri, " << fails << " parole gresite, "
           << static_cast<int>(entries_.size()) - fails << " logari reusite\n";
    }

    int printEntriesForIp(std::ostream& os, const std::string& targetIp) const {
        int matched = 0;
        for (const LogEntry& entry : entries_) {
            if (entry.matchesIpString(targetIp)) {
                os << "  " << entry << "\n";
                matched++;
            }
        }
        return matched;
    }
    friend std::ostream& operator<<(std::ostream& os, const LogSource& source) {
        return os << "SSH (" << source.sourceName_ << "): " << source.entries_.size() << " evenimente, "
                  << source.ignoredLines_ << (source.ignoredLines_ == 1 ? " linie respinsa" : " linii respinse");
    }
};

#endif

#ifndef LOG_SOURCE_H
#define LOG_SOURCE_H

#include <iostream>
#include <string>
#include <vector>
#include "LogEntry.h"

class LogSource {
private:
    std::string sourceName_;
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

    bool readNextEntry(std::istream& in) {
        std::string month;
        std::string ip;
        int day = 0;
        int hour = 0;
        int minute = 0;
        int second = 0;
        bool failed = false;

        if (!(in >> month >> day >> hour >> minute >> second >> ip >> failed)) {
            return false;
        }
        LogEntry entry(month, day, hour, minute, second, ip, failed);
        if (entry.isValid()) {
            entries_.push_back(entry);
        } else {
            ignoredLines_++;
        }
        return true;
    }

    std::string makeBar(int count, int total) const {
        if (total <= 0 || sourceName_.empty()) {
            return "[          ]";
        }
        int filled = (count * 10) / total;
        if (filled < 0) {
            filled = 0;
        }
        if (filled > 10) {
            filled = 10;
        }
        std::string bar = "[";
        for (int i = 0; i < 10; i++) {
            if (i < filled) {
                bar += '#';
            } else {
                bar += ' ';
            }
        }
        bar += "]";
        return bar;
    }

public:
    explicit LogSource(const std::string& sourceName)
        : sourceName_(sourceName), ignoredLines_(0) {}

    void ingestFromStream(std::istream& in, int lineCount) {
        for (int i = 0; i < lineCount; i++) {
            readNextEntry(in);
        }
        sortChronologically();
    }

    int ingestUntilEof(std::istream& in) {
        int recordsRead = 0;
        while (readNextEntry(in)) {
            recordsRead++;
        }
        sortChronologically();
        return recordsRead;
    }

    int getEntryCount() const {
        int count = 0;
        for (std::size_t i = 0; i < entries_.size(); i++) {
            count++;
        }
        return count;
    }

    const LogEntry& getEntryAt(int index) const {
        std::size_t idx = 0;
        for (int i = 0; i < index; i++) {
            idx++;
        }
        return entries_[idx];
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
        int validCount = source.getEntryCount();
        int totalProcessed = validCount + source.ignoredLines_;
        os << "[SSH Stream: " << source.sourceName_ << "] "
           << source.makeBar(validCount, totalProcessed) << " "
           << validCount << " valid entries (" << source.ignoredLines_ << " invalid ignored)";
        return os;
    }
};

#endif

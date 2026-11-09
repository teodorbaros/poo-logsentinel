#ifndef LOG_ENTRY_H
#define LOG_ENTRY_H

#include <iomanip>
#include <iostream>
#include <string>
#include "Ipv4Address.h"
#include "Timestamp.h"

// O incercare de autentificare SSH: cand, de la ce IP, reusita sau nu.
class LogEntry {
private:
    static constexpr int kIpColumn = 15;   // "255.255.255.255" are 15 caractere

    Timestamp timestamp_;
    Ipv4Address ip_;
    bool failed_;

public:
    LogEntry(const Timestamp& timestamp, const Ipv4Address& ip, bool failed)
        : timestamp_(timestamp), ip_(ip), failed_(failed) {}

    LogEntry(const std::string& month, int day, int hour, int minute, int second, const std::string& ip, bool failed)
        : LogEntry(Timestamp(month, day, hour, minute, second), Ipv4Address(ip), failed) {}

    bool isValid() const { return timestamp_.isValid() && ip_.isValid(); }
    bool isFailed() const { return failed_; }

    bool hasSameIp(const LogEntry& other) const { return ip_.sameAs(other.ip_); }
    bool matchesIpString(const std::string& targetIp) const { return ip_.toString() == targetIp; }
    const std::string& getIpString() const { return ip_.toString(); }
    const Ipv4Address& getAddress() const { return ip_; }
    const Timestamp& getTimestamp() const { return timestamp_; }

    int secondsSince(const LogEntry& start) const { return timestamp_.secondsSince(start.timestamp_); }

    // pentru std::sort: ordinea cronologica
    bool operator<(const LogEntry& other) const { return timestamp_.isBefore(other.timestamp_); }

    void updateCounters(int& totalAttempts, int& failedAttempts) const {
        totalAttempts++;
        if (failed_) {
            failedAttempts++;
        }
    }

    // "Oct 12 14:02:10  192.168.1.50     parola gresita"
    friend std::ostream& operator<<(std::ostream& os, const LogEntry& entry) {
        return os << entry.timestamp_ << "  " << std::left << std::setw(kIpColumn) << entry.ip_.toString() << std::right
                  << "  " << (entry.failed_ ? "parola gresita" : "logare reusita");
    }
};

#endif

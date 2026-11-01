#ifndef LOG_ENTRY_HPP
#define LOG_ENTRY_HPP

#include <iostream>
#include <string>

class LogEntry {
private:
    int timestamp_;
    std::string ip_;
    bool failed_;

    static bool isValidIpv4Format(const std::string& ip) {
        if (ip.empty() || ip.size() > 15) {
            return false;
        }

        int dots = 0;
        int currentOctet = 0;
        int digitsInOctet = 0;

        for (std::size_t i = 0; i < ip.size(); i++) {
            char c = ip[i];
            if (c == '.') {
                if (digitsInOctet == 0 || currentOctet > 255) {
                    return false;
                }
                dots++;
                currentOctet = 0;
                digitsInOctet = 0;
            } else if (c >= '0' && c <= '9') {
                currentOctet = currentOctet * 10 + (c - '0');
                digitsInOctet++;
                if (digitsInOctet > 3 || currentOctet > 255) {
                    return false;
                }
            } else {
                return false;
            }
        }

        return (dots == 3 && digitsInOctet > 0 && currentOctet <= 255);
    }

    void setTimestamp(const std::string& month, int day, int hour, int minute, int second) {
        if (day < 1 || day > 31 || hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 59) {
            timestamp_ = -1;
            return;
        }

        const std::string months[12] = {
            "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
        };
        const int daysInMonth[12] = {
            31, 28, 31, 30, 31, 30,
            31, 31, 30, 31, 30, 31
        };
        const int cumulativeDays[12] = {
            0, 31, 59, 90, 120, 151,
            181, 212, 243, 273, 304, 334
        };

        timestamp_ = -1;
        for (int i = 0; i < 12; i++) {
            if (month == months[i]) {
                if (day > daysInMonth[i]) {
                    timestamp_ = -1;
                    return;
                }
                int days = cumulativeDays[i] + day - 1;
                timestamp_ = days * 86400 + hour * 3600 + minute * 60 + second;
                return;
            }
        }
    }

    std::string formatTime() const {
        if (timestamp_ < 0) {
            return "?";
        }

        const std::string months[12] = {
            "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
        };
        const int cumulativeDays[12] = {
            0, 31, 59, 90, 120, 151,
            181, 212, 243, 273, 304, 334
        };

        int days = timestamp_ / 86400;
        int remainder = timestamp_ % 86400;

        int month = 11;
        while (month > 0 && cumulativeDays[month] > days) {
            month--;
        }

        int day = (days - cumulativeDays[month]) + 1;
        int hour = remainder / 3600;
        int minute = (remainder % 3600) / 60;
        int second = remainder % 60;

        std::string dayStr = (day < 10 ? "0" : "") + std::to_string(day);
        std::string hourStr = (hour < 10 ? "0" : "") + std::to_string(hour);
        std::string minStr = (minute < 10 ? "0" : "") + std::to_string(minute);
        std::string secStr = (second < 10 ? "0" : "") + std::to_string(second);

        return months[month] + " " + dayStr + " " + hourStr + ":" + minStr + ":" + secStr;
    }

public:
    LogEntry(const std::string& month, int day, int hour, int minute, int second, const std::string& ip, bool failed)
        : timestamp_(-1), ip_(ip), failed_(failed) {
        if (isValidIpv4Format(ip)) {
            setTimestamp(month, day, hour, minute, second);
        }
    }

    bool isValid() const {
        return timestamp_ >= 0 && !ip_.empty();
    }

    bool hasSameIp(const LogEntry& other) const {
        return ip_ == other.ip_;
    }

    bool matchesIpString(const std::string& targetIp) const {
        return ip_ == targetIp;
    }

    bool isBefore(const LogEntry& other) const {
        return timestamp_ < other.timestamp_;
    }

    int secondsSince(const LogEntry& start) const {
        return timestamp_ - start.timestamp_;
    }

    bool hasWindowExpired(const LogEntry& start, int windowSeconds) const {
        return (timestamp_ - start.timestamp_) > windowSeconds;
    }

    void updateCounters(int& totalAttempts, int& failedAttempts) const {
        totalAttempts++;
        if (failed_) {
            failedAttempts++;
        }
    }

    void printAlertFormat(std::ostream& os, const std::string& category, const std::string& severity, const std::string& message) const {
        os << "[" << category << ":" << severity << "] IP " << ip_ << " - " << message << " (at " << formatTime() << ")";
    }

    friend std::ostream& operator<<(std::ostream& os, const LogEntry& entry) {
        os << "[SSH " << entry.formatTime() << "] " << entry.ip_ << " " << (entry.failed_ ? "FAILED" : "SUCCESS");
        return os;
    }
};

#endif // LOG_ENTRY_HPP

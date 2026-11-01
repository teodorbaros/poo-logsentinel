#pragma once

#include <ostream>
#include <string>
#include <vector>

#include "LogEntry.hpp"

class FirewallEntry {
private:
    int timestamp_;
    std::string sourceIp_;
    int destPort_;
    std::string protocol_;
    bool blocked_;

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

    static bool isValidPortAndProtocol(int port, const std::string& proto) {
        bool validPort = (port >= 1 && port <= 65535);
        bool validProto = (proto == "TCP" || proto == "UDP" || proto == "ICMP");
        return validPort && validProto;
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
    FirewallEntry(const std::string& month, int day, int hour, int minute, int second,
                  const std::string& sourceIp, int destPort, const std::string& protocol, bool blocked)
        : timestamp_(-1), sourceIp_(sourceIp), destPort_(destPort), protocol_(protocol), blocked_(blocked) {
        if (isValidIpv4Format(sourceIp) && isValidPortAndProtocol(destPort, protocol)) {
            setTimestamp(month, day, hour, minute, second);
        }
    }

    bool isValid() const {
        return timestamp_ >= 0 && !sourceIp_.empty();
    }

    bool hasSameSourceIp(const FirewallEntry& other) const {
        return sourceIp_ == other.sourceIp_;
    }

    bool matchesIpString(const std::string& targetIp) const {
        return sourceIp_ == targetIp;
    }

    bool matchesLogEntryIp(const LogEntry& sshEntry) const {
        return sshEntry.matchesIpString(sourceIp_);
    }

    bool isBefore(const FirewallEntry& other) const {
        return timestamp_ < other.timestamp_;
    }

    int secondsSince(const FirewallEntry& start) const {
        return timestamp_ - start.timestamp_;
    }

    bool hasWindowExpired(const FirewallEntry& start, int windowSeconds) const {
        return (timestamp_ - start.timestamp_) > windowSeconds;
    }

    bool targetsCriticalService() const {
        const int criticalPorts[7] = {21, 22, 23, 445, 1433, 3306, 3389};
        for (int i = 0; i < 7; i++) {
            if (destPort_ == criticalPorts[i]) {
                return true;
            }
        }
        return false;
    }

    void updateScanMetrics(std::vector<int>& distinctPorts, int& blockedCount, int& criticalHits) const {
        if (!blocked_) {
            return;
        }
        blockedCount++;
        if (targetsCriticalService()) {
            criticalHits++;
        }

        bool alreadyRecorded = false;
        for (std::size_t i = 0; i < distinctPorts.size(); i++) {
            if (distinctPorts[i] == destPort_) {
                alreadyRecorded = true;
                break;
            }
        }
        if (!alreadyRecorded) {
            distinctPorts.push_back(destPort_);
        }
    }

    void updateFirewallStats(std::vector<std::string>& ips, std::vector<int>& ports, std::vector<int>& portHits,
                             int& blockedCount, int& criticalPackets, int& tcp, int& udp, int& icmp) const {
        if (blocked_) {
            blockedCount++;
        }
        if (targetsCriticalService()) {
            criticalPackets++;
        }
        if (protocol_ == "TCP") {
            tcp++;
        } else if (protocol_ == "UDP") {
            udp++;
        } else if (protocol_ == "ICMP") {
            icmp++;
        }

        bool ipKnown = false;
        for (std::size_t j = 0; j < ips.size(); j++) {
            if (ips[j] == sourceIp_) {
                ipKnown = true;
                break;
            }
        }
        if (!ipKnown) {
            ips.push_back(sourceIp_);
        }

        std::size_t pidx = ports.size();
        for (std::size_t j = 0; j < ports.size(); j++) {
            if (ports[j] == destPort_) {
                pidx = j;
                break;
            }
        }
        if (pidx == ports.size()) {
            ports.push_back(destPort_);
            portHits.push_back(0);
        }
        portHits[pidx]++;
    }

    LogEntry toTriggerEntry() const {
        if (timestamp_ < 0) {
            return LogEntry("Jan", 1, 0, 0, 0, sourceIp_, blocked_);
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

        return LogEntry(months[month], day, hour, minute, second, sourceIp_, blocked_);
    }

    friend std::ostream& operator<<(std::ostream& os, const FirewallEntry& fw) {
        os << "[FW  " << fw.formatTime() << "] " << (fw.blocked_ ? "BLOCK" : "ALLOW")
           << " " << fw.protocol_ << " from " << fw.sourceIp_ << " -> port " << fw.destPort_;
        return os;
    }
};

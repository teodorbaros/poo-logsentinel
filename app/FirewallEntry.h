#ifndef FIREWALL_ENTRY_H
#define FIREWALL_ENTRY_H

#include <algorithm>
#include <array>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>
#include "Ipv4Address.h"
#include "LogEntry.h"
#include "Timestamp.h"

// Un pachet vazut de firewall: cand, de la ce IP, spre ce port, blocat sau permis.
class FirewallEntry {
private:
    static constexpr int kMaxPort = 65535;
    static constexpr int kIpColumn = 15;
    static constexpr int kStatusColumn = 8;   // "blocat" / "permis" + spatiu
    // FTP, SSH, Telnet, SMB, MSSQL, MySQL, RDP
    static constexpr std::array<int, 7> kCriticalPorts = {21, 22, 23, 445, 1433, 3306, 3389};

    Timestamp timestamp_;
    Ipv4Address sourceIp_;
    int destPort_;
    std::string protocol_;
    bool blocked_;

public:
    FirewallEntry(const std::string& month, int day, int hour, int minute, int second, const std::string& sourceIp,
                  int destPort, const std::string& protocol, bool blocked)
        : timestamp_(month, day, hour, minute, second),
          sourceIp_(sourceIp),
          destPort_(destPort),
          protocol_(protocol),
          blocked_(blocked) {}

    bool isValid() const {
        const bool validProtocol = protocol_ == "TCP" || protocol_ == "UDP" || protocol_ == "ICMP";
        return timestamp_.isValid() && sourceIp_.isValid() && destPort_ >= 1 && destPort_ <= kMaxPort && validProtocol;
    }

    bool isBlocked() const { return blocked_; }
    int getDestPort() const { return destPort_; }
    bool hasSameSourceIp(const FirewallEntry& other) const { return sourceIp_.sameAs(other.sourceIp_); }
    bool matchesIpString(const std::string& targetIp) const { return sourceIp_.toString() == targetIp; }
    const std::string& getIpString() const { return sourceIp_.toString(); }
    const Ipv4Address& getAddress() const { return sourceIp_; }
    const Timestamp& getTimestamp() const { return timestamp_; }

    int secondsSince(const FirewallEntry& start) const { return timestamp_.secondsSince(start.timestamp_); }

    bool operator<(const FirewallEntry& other) const { return timestamp_.isBefore(other.timestamp_); }

    bool targetsCriticalService() const {
        return std::find(kCriticalPorts.begin(), kCriticalPorts.end(), destPort_) != kCriticalPorts.end();
    }

    // Adauga pachetul la statisticile unui port scan (doar pachetele blocate conteaza)
    void updateScanMetrics(std::vector<int>& distinctPorts, int& blockedCount, int& criticalHits) const {
        if (!blocked_) {
            return;
        }
        blockedCount++;
        if (targetsCriticalService()) {
            criticalHits++;
        }
        if (std::find(distinctPorts.begin(), distinctPorts.end(), destPort_) == distinctPorts.end()) {
            distinctPorts.push_back(destPort_);
        }
    }

    // Alertele au nevoie de un LogEntry ca "declansator" (moment + IP)
    LogEntry toTriggerEntry() const { return {timestamp_, sourceIp_, blocked_}; }

    // "Oct 12 14:01:05  203.0.113.77     blocat    TCP port 22 (serviciu critic)"
    friend std::ostream& operator<<(std::ostream& os, const FirewallEntry& fw) {
        os << fw.timestamp_ << "  " << std::left << std::setw(kIpColumn) << fw.sourceIp_.toString() << "  "
           << std::setw(kStatusColumn) << (fw.blocked_ ? "blocat" : "permis") << std::right << "  " << fw.protocol_ << " port "
           << fw.destPort_;
        if (fw.targetsCriticalService()) {
            os << " (serviciu critic)";
        }
        return os;
    }
};

#endif

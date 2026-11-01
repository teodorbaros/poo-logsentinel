#pragma once

#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "FirewallEntry.hpp"
#include "Utils.hpp"

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

    void printStatistics(std::ostream& os) const {
        os << "--- Firewall Statistics ---\n";
        if (entries_.empty()) {
            os << "  (no data)\n";
            return;
        }

        std::vector<std::string> ips;
        std::vector<int> ports;
        std::vector<int> portHits;
        int blocked = 0;
        int criticalPackets = 0;
        int tcp = 0;
        int udp = 0;
        int icmp = 0;

        for (std::size_t i = 0; i < entries_.size(); i++) {
            const FirewallEntry& e = entries_[i];
            if (e.blocked_) {
                blocked++;
            }
            if (e.targetsCriticalService()) {
                criticalPackets++;
            }
            if (e.protocol_ == "TCP") {
                tcp++;
            } else if (e.protocol_ == "UDP") {
                udp++;
            } else if (e.protocol_ == "ICMP") {
                icmp++;
            }

            bool ipKnown = false;
            for (std::size_t j = 0; j < ips.size(); j++) {
                if (ips[j] == e.sourceIp_) {
                    ipKnown = true;
                    break;
                }
            }
            if (!ipKnown) {
                ips.push_back(e.sourceIp_);
            }

            int pidx = -1;
            for (std::size_t j = 0; j < ports.size(); j++) {
                if (ports[j] == e.destPort_) {
                    pidx = static_cast<int>(j);
                    break;
                }
            }
            if (pidx < 0) {
                ports.push_back(e.destPort_);
                portHits.push_back(0);
                pidx = static_cast<int>(ports.size()) - 1;
            }
            portHits[pidx]++;
        }

        int total = static_cast<int>(entries_.size());
        int allowed = total - blocked;
        double blockRate = 100.0 * blocked / total;
        double allowRate = 100.0 - blockRate;
        double criticalRate = 100.0 * criticalPackets / total;

        int topPort = 0;
        for (std::size_t j = 1; j < ports.size(); j++) {
            if (portHits[j] > portHits[topPort]) {
                topPort = static_cast<int>(j);
            }
        }

        std::ios::fmtflags oldFlags = os.flags();
        std::streamsize oldPrecision = os.precision();
        os << std::fixed << std::setprecision(1);

        os << "  Total packets      : " << total << "\n";
        os << "  Allowed            : " << allowed << " (" << allowRate << "%) " << makeBar(allowRate) << "\n";
        os << "  Blocked            : " << blocked << " (" << blockRate << "%) " << makeBar(blockRate) << "\n";
        os << "  Critical-port hits : " << criticalPackets << " (" << criticalRate << "%) " << makeBar(criticalRate) << "\n";
        os << "  Distinct source IPs: " << ips.size() << "\n";
        os << "  Distinct ports     : " << ports.size() << "\n";
        os << "  Most targeted port : " << ports[topPort] << " (" << portHits[topPort] << " packets)\n";
        os << "  Protocols          : TCP=" << tcp << ", UDP=" << udp << ", ICMP=" << icmp << "\n";
        os << "  First packet       : " << entries_.front() << "\n";
        os << "  Last packet        : " << entries_.back() << "\n";

        os.flags(oldFlags);
        os.precision(oldPrecision);
    }

    friend std::ostream& operator<<(std::ostream& os, const FirewallSource& source) {
        os << "[FW Source]\n"
           << "    File            : " << source.filePath_ << "\n"
           << "    Valid packets   : " << source.entries_.size() << "\n"
           << "    Invalid ignored : " << source.ignoredLines_;
        return os;
    }
};


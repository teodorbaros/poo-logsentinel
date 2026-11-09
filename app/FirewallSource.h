#ifndef FIREWALL_SOURCE_H
#define FIREWALL_SOURCE_H

#include <algorithm>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <vector>
#include "FirewallEntry.h"

// Toate pachetele de firewall incarcate, in ordine cronologica.
class FirewallSource {
private:
    std::string sourceName_;
    std::vector<FirewallEntry> entries_;
    int ignoredLines_;

    // Citeste o linie "Luna Zi Ora Min Sec IP port protocol blocked"; o pastreaza doar daca e valida.
    bool readEntry(std::istream& in) {
        std::string month;
        std::string ip;
        std::string protocol;
        int day = 0;
        int hour = 0;
        int minute = 0;
        int second = 0;
        int port = 0;
        bool blocked = false;
        if (in >> month >> day >> hour >> minute >> second >> ip >> port >> protocol >> blocked) {
            const FirewallEntry entry(month, day, hour, minute, second, ip, port, protocol, blocked);
            if (entry.isValid()) {
                entries_.push_back(entry);
                return true;
            }
        }
        ignoredLines_++;
        return false;
    }

public:
    explicit FirewallSource(const std::string& sourceName) : sourceName_(sourceName), ignoredLines_(0) {}

    int ingestFromStream(std::istream& in, int packetCount) {
        int added = 0;
        for (int i = 0; i < packetCount; i++) {
            added += readEntry(in) ? 1 : 0;
        }
        std::stable_sort(entries_.begin(), entries_.end());   // "stable": la aceeasi ora pastreaza ordinea din input
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
        std::stable_sort(entries_.begin(), entries_.end());   // "stable": la aceeasi ora pastreaza ordinea din input
        return added;
    }

    int getEntryCount() const { return static_cast<int>(entries_.size()); }
    int getRejectedCount() const { return ignoredLines_; }
    const FirewallEntry& getEntryAt(int index) const { return entries_[static_cast<std::size_t>(index)]; }

    //   interval: Oct 12 14:01:05 - Oct 12 14:25:40
    //   8 IP-uri, 15 blocate, 8 permise, 12 porturi diferite (4 pe servicii critice)
    void printTelemetrySummary(std::ostream& os) const {
        if (entries_.empty()) {
            return;
        }
        std::set<std::string> uniqueIps;
        std::set<int> distinctPorts;
        int blocked = 0;
        int critical = 0;
        for (const FirewallEntry& entry : entries_) {
            uniqueIps.insert(entry.getIpString());
            distinctPorts.insert(entry.getDestPort());
            blocked += entry.isBlocked() ? 1 : 0;
            critical += entry.targetsCriticalService() ? 1 : 0;
        }
        os << "  interval: " << entries_.front().getTimestamp() << " - " << entries_.back().getTimestamp() << "\n"
           << "  " << uniqueIps.size() << " IP-uri, " << blocked << " blocate, " << static_cast<int>(entries_.size()) - blocked
           << " permise, " << distinctPorts.size() << " porturi diferite, " << critical << " pachete spre servicii critice\n";
    }

    int printPacketsForIp(std::ostream& os, const std::string& targetIp) const {
        int matched = 0;
        for (const FirewallEntry& entry : entries_) {
            if (entry.matchesIpString(targetIp)) {
                os << "  " << entry << "\n";
                matched++;
            }
        }
        return matched;
    }

    // "Firewall (ufw): 23 pachete, 1 linie respinsa"
    friend std::ostream& operator<<(std::ostream& os, const FirewallSource& source) {
        return os << "Firewall (" << source.sourceName_ << "): " << source.entries_.size() << " pachete, "
                  << source.ignoredLines_ << (source.ignoredLines_ == 1 ? " linie respinsa" : " linii respinse");
    }
};

#endif

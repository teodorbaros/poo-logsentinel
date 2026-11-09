#ifndef PORT_SCAN_TRACKER_H
#define PORT_SCAN_TRACKER_H

#include <iostream>
#include <sstream>
#include <vector>
#include "Alert.h"
#include "DetectionPolicy.h"
#include "FirewallEntry.h"

// Tine porturile distincte lovite de un IP intr-o fereastra de timp (pentru port scan).
class PortScanTracker {
private:
    FirewallEntry firstPacket_;
    std::vector<int> distinctPorts_;
    int blockedPackets_;
    int criticalPortHits_;

    int distinctPortCount() const { return static_cast<int>(distinctPorts_.size()); }

public:
    explicit PortScanTracker(const FirewallEntry& firstPacket)
        : firstPacket_(firstPacket), blockedPackets_(0), criticalPortHits_(0) {
        firstPacket.updateScanMetrics(distinctPorts_, blockedPackets_, criticalPortHits_);
    }

    bool tracksSameIp(const FirewallEntry& entry) const { return firstPacket_.hasSameSourceIp(entry); }

    void recordPacket(const FirewallEntry& entry, const DetectionPolicy& policy) {
        if (policy.isOutsideWindow(entry.secondsSince(firstPacket_))) {
            firstPacket_ = entry;
            distinctPorts_.clear();
            blockedPackets_ = 0;
            criticalPortHits_ = 0;
        }
        entry.updateScanMetrics(distinctPorts_, blockedPackets_, criticalPortHits_);
    }

    bool isPortScan(const DetectionPolicy& policy) const { return policy.isPortScan(distinctPortCount()); }

    // merita aratat ca "de urmarit" doar daca a lovit macar un port blocat
    bool hasBlockedPorts() const { return distinctPortCount() > 0; }

    // risc = porturi distincte + lovituri pe servicii critice
    Alert createScanAlert(const FirewallEntry& lastPacket) const {
        std::ostringstream msg;
        msg << distinctPortCount() << " porturi blocate in " << lastPacket.secondsSince(firstPacket_) << " s";
        if (criticalPortHits_ > 0) {
            msg << ", " << criticalPortHits_ << " critice";
        }
        return {"port scan", msg.str(), lastPacket.toTriggerEntry(), distinctPortCount() + criticalPortHits_};
    }

    friend std::ostream& operator<<(std::ostream& os, const PortScanTracker& tracker) {
        const int ports = tracker.distinctPortCount();
        return os << tracker.firstPacket_.getIpString() << ": " << ports << (ports == 1 ? " port blocat" : " porturi blocate")
                  << " (de la " << tracker.firstPacket_.getTimestamp() << ")";
    }
};

#endif

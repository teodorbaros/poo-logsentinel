#ifndef PORT_SCAN_TRACKER_H
#define PORT_SCAN_TRACKER_H

#include <iostream>
#include <sstream>
#include <vector>
#include "FirewallEntry.h"
#include "Alert.h"

class PortScanTracker {
private:
    FirewallEntry firstPacket_;
    std::vector<int> distinctPorts_;
    int blockedPackets_;
    int criticalPortHits_;

public:
    explicit PortScanTracker(const FirewallEntry& firstPacket)
        : firstPacket_(firstPacket), blockedPackets_(0), criticalPortHits_(0) {
        firstPacket.updateScanMetrics(distinctPorts_, blockedPackets_, criticalPortHits_);
    }

    bool tracksSameIp(const FirewallEntry& entry) const {
        return firstPacket_.hasSameSourceIp(entry);
    }

    void recordPacket(const FirewallEntry& entry, int windowSeconds) {
        if (entry.hasWindowExpired(firstPacket_, windowSeconds)) {
            firstPacket_ = entry;
            distinctPorts_.clear();
            blockedPackets_ = 0;
            criticalPortHits_ = 0;
        }
        entry.updateScanMetrics(distinctPorts_, blockedPackets_, criticalPortHits_);
    }

    bool isPortScan(int minDistinctPorts) const {
        int portCount = 0;
        for (std::size_t i = 0; i < distinctPorts_.size(); i++) {
            portCount++;
        }
        return portCount >= minDistinctPorts;
    }

    Alert createScanAlert(const FirewallEntry& lastPacket) const {
        int duration = lastPacket.secondsSince(firstPacket_);
        int portCount = 0;
        for (std::size_t i = 0; i < distinctPorts_.size(); i++) {
            portCount++;
        }
        std::ostringstream msg;
        msg << portCount << " distinct ports probed (" << blockedPackets_
            << " blocked packets, " << criticalPortHits_ << " critical services) in " << duration << "s";
        int riskScore = portCount + criticalPortHits_;
        return Alert("FW-PORTSCAN", msg.str(), lastPacket.toTriggerEntry(), riskScore);
    }

    friend std::ostream& operator<<(std::ostream& os, const PortScanTracker& tracker) {
        os << tracker.firstPacket_ << " -> " << tracker.distinctPorts_.size()
           << " distinct ports (" << tracker.blockedPackets_ << " blocked)";
        return os;
    }
};

#endif

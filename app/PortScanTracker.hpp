#ifndef PORT_SCAN_TRACKER_HPP
#define PORT_SCAN_TRACKER_HPP

#include <iostream>
#include <sstream>
#include <vector>
#include "FirewallEntry.hpp"
#include "Alert.hpp"

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
        return static_cast<int>(distinctPorts_.size()) >= minDistinctPorts;
    }

    Alert createScanAlert(const FirewallEntry& lastPacket) const {
        int duration = lastPacket.secondsSince(firstPacket_);
        std::ostringstream msg;
        msg << distinctPorts_.size() << " distinct ports probed (" << blockedPackets_
            << " blocked packets, " << criticalPortHits_ << " critical services) in " << duration << "s";
        int riskScore = static_cast<int>(distinctPorts_.size()) + criticalPortHits_;
        return Alert("FW-PORTSCAN", msg.str(), lastPacket.toTriggerEntry(), riskScore);
    }

    friend std::ostream& operator<<(std::ostream& os, const PortScanTracker& tracker) {
        os << tracker.firstPacket_ << " -> " << tracker.distinctPorts_.size()
           << " distinct ports (" << tracker.blockedPackets_ << " blocked)";
        return os;
    }
};

#endif // PORT_SCAN_TRACKER_HPP

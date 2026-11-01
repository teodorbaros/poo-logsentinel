#ifndef ANALYZER_H
#define ANALYZER_H

#include <iostream>
#include <string>
#include <vector>
#include "LogSource.h"
#include "FirewallSource.h"
#include "IpTracker.h"
#include "PortScanTracker.h"
#include "Alert.h"

class Analyzer {
private:
    LogSource sshSource_;
    FirewallSource fwSource_;
    int sshThreshold_;
    int portScanThreshold_;
    int windowSeconds_;
    double minFailureRatio_;
    std::vector<IpTracker> sshTrackers_;
    std::vector<PortScanTracker> fwTrackers_;
    std::vector<Alert> sshAlerts_;
    std::vector<Alert> fwAlerts_;
    std::vector<Alert> correlatedAlerts_;

    int findSshTrackerIndex(const LogEntry& entry) const {
        int index = 0;
        for (std::size_t i = 0; i < sshTrackers_.size(); i++) {
            if (sshTrackers_[i].tracksSameIp(entry)) {
                return index;
            }
            index++;
        }
        return -1;
    }

    int findFwTrackerIndex(const FirewallEntry& entry) const {
        int index = 0;
        for (std::size_t i = 0; i < fwTrackers_.size(); i++) {
            if (fwTrackers_[i].tracksSameIp(entry)) {
                return index;
            }
            index++;
        }
        return -1;
    }

public:
    explicit Analyzer(const LogSource& sshSource, const FirewallSource& fwSource,
                      int sshThreshold = 5, int portScanThreshold = 4,
                      int windowSeconds = 60, double minFailureRatio = 0.8)
        : sshSource_(sshSource),
          fwSource_(fwSource),
          sshThreshold_(sshThreshold),
          portScanThreshold_(portScanThreshold),
          windowSeconds_(windowSeconds),
          minFailureRatio_(minFailureRatio) {}

    void syncSources(const LogSource& sshSource, const FirewallSource& fwSource) {
        sshSource_ = sshSource;
        fwSource_ = fwSource;
    }

    void updatePolicy(int sshThreshold, int portScanThreshold, int windowSeconds, double minFailureRatio) {
        if (sshThreshold > 0) {
            sshThreshold_ = sshThreshold;
        }
        if (portScanThreshold > 0) {
            portScanThreshold_ = portScanThreshold;
        }
        if (windowSeconds > 0) {
            windowSeconds_ = windowSeconds;
        }
        if (minFailureRatio > 0.0 && minFailureRatio <= 1.0) {
            minFailureRatio_ = minFailureRatio;
        }
    }

    int detectSshBruteForce() {
        sshTrackers_.clear();
        sshAlerts_.clear();

        for (int i = 0; i < sshSource_.getEntryCount(); i++) {
            const LogEntry& entry = sshSource_.getEntryAt(i);
            int index = findSshTrackerIndex(entry);

            if (index < 0) {
                sshTrackers_.push_back(IpTracker(entry));
                index = 0;
                for (std::size_t k = 0; k + 1 < sshTrackers_.size(); k++) {
                    index++;
                }
            } else {
                std::size_t pos = 0;
                for (int k = 0; k < index; k++) {
                    pos++;
                }
                sshTrackers_[pos].recordAttempt(entry, windowSeconds_);
            }

            std::size_t currentIdx = 0;
            for (int k = 0; k < index; k++) {
                currentIdx++;
            }
            if (sshTrackers_[currentIdx].isAttack(sshThreshold_, minFailureRatio_)) {
                sshAlerts_.push_back(sshTrackers_[currentIdx].createAlert(entry));
                sshTrackers_.erase(sshTrackers_.begin() + index);
            }
        }

        int alertCount = 0;
        for (std::size_t i = 0; i < sshAlerts_.size(); i++) {
            alertCount++;
        }
        return alertCount;
    }

    int detectFirewallPortScans() {
        fwTrackers_.clear();
        fwAlerts_.clear();

        for (int i = 0; i < fwSource_.getEntryCount(); i++) {
            const FirewallEntry& packet = fwSource_.getEntryAt(i);
            int index = findFwTrackerIndex(packet);

            if (index < 0) {
                fwTrackers_.push_back(PortScanTracker(packet));
                index = 0;
                for (std::size_t k = 0; k + 1 < fwTrackers_.size(); k++) {
                    index++;
                }
            } else {
                std::size_t pos = 0;
                for (int k = 0; k < index; k++) {
                    pos++;
                }
                fwTrackers_[pos].recordPacket(packet, windowSeconds_);
            }

            std::size_t currentIdx = 0;
            for (int k = 0; k < index; k++) {
                currentIdx++;
            }
            if (fwTrackers_[currentIdx].isPortScan(portScanThreshold_)) {
                fwAlerts_.push_back(fwTrackers_[currentIdx].createScanAlert(packet));
                fwTrackers_.erase(fwTrackers_.begin() + index);
            }
        }

        int alertCount = 0;
        for (std::size_t i = 0; i < fwAlerts_.size(); i++) {
            alertCount++;
        }
        return alertCount;
    }

    int correlateMultiStageAttacks() {
        correlatedAlerts_.clear();

        for (std::size_t i = 0; i < fwAlerts_.size(); i++) {
            for (std::size_t j = 0; j < sshAlerts_.size(); j++) {
                if (fwAlerts_[i].involvesSameIpAs(sshAlerts_[j])) {
                    correlatedAlerts_.push_back(fwAlerts_[i].promoteToCorrelatedAlert(sshAlerts_[j]));
                }
            }
        }

        int corrCount = 0;
        for (std::size_t i = 0; i < correlatedAlerts_.size(); i++) {
            corrCount++;
        }
        return corrCount;
    }

    int runFullSiemAnalysis() {
        int sshCount = detectSshBruteForce();
        int fwCount = detectFirewallPortScans();
        int corrCount = correlateMultiStageAttacks();
        return sshCount + fwCount + corrCount;
    }

    int countHighSeverityIncidents() const {
        int count = 0;
        for (std::size_t i = 0; i < sshAlerts_.size(); i++) {
            if (sshAlerts_[i].isHighOrCritical()) {
                count++;
            }
        }
        for (std::size_t i = 0; i < fwAlerts_.size(); i++) {
            if (fwAlerts_[i].isHighOrCritical()) {
                count++;
            }
        }
        for (std::size_t i = 0; i < correlatedAlerts_.size(); i++) {
            if (correlatedAlerts_[i].isHighOrCritical()) {
                count++;
            }
        }
        return count;
    }

    void printAlertsForIp(std::ostream& os, const std::string& targetIp) const {
        for (std::size_t i = 0; i < fwAlerts_.size(); i++) {
            if (fwAlerts_[i].matchesIpString(targetIp)) {
                os << "  " << fwAlerts_[i] << "\n";
            }
        }
        for (std::size_t i = 0; i < sshAlerts_.size(); i++) {
            if (sshAlerts_[i].matchesIpString(targetIp)) {
                os << "  " << sshAlerts_[i] << "\n";
            }
        }
        for (std::size_t i = 0; i < correlatedAlerts_.size(); i++) {
            if (correlatedAlerts_[i].matchesIpString(targetIp)) {
                os << "  " << correlatedAlerts_[i] << "\n";
            }
        }
    }

    bool hasAnyAlerts() const {
        return !correlatedAlerts_.empty() || !sshAlerts_.empty() || !fwAlerts_.empty();
    }

    Alert getTopPriorityAlert() const {
        if (!correlatedAlerts_.empty()) {
            return correlatedAlerts_[0];
        }
        if (!sshAlerts_.empty()) {
            return sshAlerts_[0];
        }
        return fwAlerts_[0];
    }

    void printActiveTrackers(std::ostream& os) const {
        os << "Active SSH Trackers (" << sshTrackers_.size() << "):\n";
        for (std::size_t i = 0; i < sshTrackers_.size(); i++) {
            os << "  " << sshTrackers_[i] << "\n";
        }
        os << "Active Firewall Trackers (" << fwTrackers_.size() << "):\n";
        for (std::size_t i = 0; i < fwTrackers_.size(); i++) {
            os << "  " << fwTrackers_[i] << "\n";
        }
    }

    void printReport(std::ostream& os) const {
        os << "--- A. Firewall Port Scan Alerts (" << fwAlerts_.size() << ") ---\n";
        for (std::size_t i = 0; i < fwAlerts_.size(); i++) {
            os << "  " << fwAlerts_[i] << "\n";
        }

        os << "--- B. SSH Brute-Force Alerts (" << sshAlerts_.size() << ") ---\n";
        for (std::size_t i = 0; i < sshAlerts_.size(); i++) {
            os << "  " << sshAlerts_[i] << "\n";
        }

        os << "--- C. Cross-Log Correlated SIEM Alerts (" << correlatedAlerts_.size() << ") ---\n";
        for (std::size_t i = 0; i < correlatedAlerts_.size(); i++) {
            os << "  " << correlatedAlerts_[i] << "\n";
        }
    }

    friend std::ostream& operator<<(std::ostream& os, const Analyzer& analyzer) {
        analyzer.printReport(os);
        return os;
    }
};

#endif

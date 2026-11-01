#pragma once
#include <ostream>
#include <string>
#include <vector>

#include "Alert.hpp"
#include "FirewallSource.hpp"
#include "IpTracker.hpp"
#include "LogSource.hpp"
#include "PortScanTracker.hpp"

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
        for (std::size_t i = 0; i < sshTrackers_.size(); i++) {
            if (sshTrackers_[i].tracksSameIp(entry)) {
                return static_cast<int>(i);
            }
        }
        return -1;
    }

    int findFwTrackerIndex(const FirewallEntry& entry) const {
        for (std::size_t i = 0; i < fwTrackers_.size(); i++) {
            if (fwTrackers_[i].tracksSameIp(entry)) {
                return static_cast<int>(i);
            }
        }
        return -1;
    }

    static std::string makeBar(double percent) {
        int filled = static_cast<int>(percent / 5.0);
        std::string bar = "[";
        for (int i = 0; i < 20; i++) {
            if (i < filled) {
                bar = bar + "#";
            } else {
                bar = bar + "-";
            }
        }
        return bar + "]";
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

        for (std::size_t i = 0; i < sshSource_.getEntryCount(); i++) {
            const LogEntry& entry = sshSource_.getEntryAt(i);
            int index = findSshTrackerIndex(entry);

            if (index < 0) {
                sshTrackers_.push_back(IpTracker(entry));
                index = static_cast<int>(sshTrackers_.size()) - 1;
            } else {
                sshTrackers_[static_cast<std::size_t>(index)].recordAttempt(entry, windowSeconds_);
            }

            std::size_t currentIdx = static_cast<std::size_t>(index);
            if (sshTrackers_[currentIdx].isAttack(sshThreshold_, minFailureRatio_)) {
                sshAlerts_.push_back(sshTrackers_[currentIdx].createAlert(entry));
                sshTrackers_.erase(sshTrackers_.begin() + index);
            }
        }
        return static_cast<int>(sshAlerts_.size());
    }

    int detectFirewallPortScans() {
        fwTrackers_.clear();
        fwAlerts_.clear();

        for (std::size_t i = 0; i < fwSource_.getEntryCount(); i++) {
            const FirewallEntry& packet = fwSource_.getEntryAt(i);
            int index = findFwTrackerIndex(packet);

            if (index < 0) {
                fwTrackers_.push_back(PortScanTracker(packet));
                index = static_cast<int>(fwTrackers_.size()) - 1;
            } else {
                fwTrackers_[static_cast<std::size_t>(index)].recordPacket(packet, windowSeconds_);
            }

            std::size_t currentIdx = static_cast<std::size_t>(index);
            if (fwTrackers_[currentIdx].isPortScan(portScanThreshold_)) {
                fwAlerts_.push_back(fwTrackers_[currentIdx].createScanAlert(packet));
                fwTrackers_.erase(fwTrackers_.begin() + index);
            }
        }
        return static_cast<int>(fwAlerts_.size());
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
        return static_cast<int>(correlatedAlerts_.size());
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
        os << "\n--- Active Trackers (no alert triggered yet) ---\n";
        os << "Active SSH Trackers (" << sshTrackers_.size() << "):\n";
        if (sshTrackers_.empty()) {
            os << "  (none)\n";
        }
        for (std::size_t i = 0; i < sshTrackers_.size(); i++) {
            os << "  #" << (i + 1) << " " << sshTrackers_[i] << "\n";
        }
        os << "Active Firewall Trackers (" << fwTrackers_.size() << "):\n";
        if (fwTrackers_.empty()) {
            os << "  (none)\n";
        }
        for (std::size_t i = 0; i < fwTrackers_.size(); i++) {
            os << "  #" << (i + 1) << " " << fwTrackers_[i] << "\n";
        }
    }

    void printReport(std::ostream& os) const {
        os << "\n+-------------------------------------------------------+\n";
        os << "|                  SIEM ANALYSIS REPORT                 |\n";
        os << "+-------------------------------------------------------+\n";
        os << "Policy in use:\n";
        os << "  SSH failure threshold : " << sshThreshold_ << "\n";
        os << "  Port scan threshold   : " << portScanThreshold_ << " distinct ports\n";
        os << "  Time window           : " << windowSeconds_ << "s\n";
        os << "  Min failure ratio     : " << minFailureRatio_ << "\n\n";

        os << "--- A. Firewall Port Scan Alerts (" << fwAlerts_.size() << ") ---\n";
        if (fwAlerts_.empty()) {
            os << "  (none)\n";
        }
        for (std::size_t i = 0; i < fwAlerts_.size(); i++) {
            os << "  #" << (i + 1) << " " << fwAlerts_[i] << "\n";
        }

        os << "\n--- B. SSH Brute-Force Alerts (" << sshAlerts_.size() << ") ---\n";
        if (sshAlerts_.empty()) {
            os << "  (none)\n";
        }
        for (std::size_t i = 0; i < sshAlerts_.size(); i++) {
            os << "  #" << (i + 1) << " " << sshAlerts_[i] << "\n";
        }

        os << "\n--- C. Cross-Log Correlated SIEM Alerts (" << correlatedAlerts_.size() << ") ---\n";
        if (correlatedAlerts_.empty()) {
            os << "  (none)\n";
        }
        for (std::size_t i = 0; i < correlatedAlerts_.size(); i++) {
            os << "  #" << (i + 1) << " " << correlatedAlerts_[i] << "\n";
        }

        os << "\n--- Summary ---\n";
        os << "  Firewall alerts    : " << fwAlerts_.size() << "\n";
        os << "  SSH alerts         : " << sshAlerts_.size() << "\n";
        os << "  Correlated alerts  : " << correlatedAlerts_.size() << "\n";
        os << "  Total              : "
           << (fwAlerts_.size() + sshAlerts_.size() + correlatedAlerts_.size()) << "\n";
    }

    void printStatistics(std::ostream& os) const {
        os << "--- Alert Statistics ---\n";
        int total = static_cast<int>(sshAlerts_.size() + fwAlerts_.size() + correlatedAlerts_.size());
        if (total == 0) {
            os << "  No alerts generated.\n";
            return;
        }

        std::vector<Alert> allAlerts = sshAlerts_;
        for (std::size_t i = 0; i < fwAlerts_.size(); i++) {
            allAlerts.push_back(fwAlerts_[i]);
        }
        for (std::size_t i = 0; i < correlatedAlerts_.size(); i++) {
            allAlerts.push_back(correlatedAlerts_[i]);
        }

        int medium = 0;
        int high = 0;
        int critical = 0;
        std::vector<std::string> ips;
        std::vector<int> counts;

        for (std::size_t i = 0; i < allAlerts.size(); i++) {
            if (allAlerts[i].severity_ == "CRITICAL") {
                critical++;
            } else if (allAlerts[i].severity_ == "HIGH") {
                high++;
            } else {
                medium++;
            }

            const std::string& ip = allAlerts[i].trigger_.ip_;
            std::size_t idx = ips.size();
            for (std::size_t j = 0; j < ips.size(); j++) {
                if (ips[j] == ip) {
                    idx = j;
                    break;
                }
            }
            if (idx == ips.size()) {
                ips.push_back(ip);
                counts.push_back(0);
            }
            counts[idx]++;
        }

        std::size_t top = 0;
        for (std::size_t j = 1; j < ips.size(); j++) {
            if (counts[j] > counts[top]) {
                top = j;
            }
        }

        int events = static_cast<int>(sshSource_.getEntryCount() + fwSource_.getEntryCount());
        int mediumPct = static_cast<int>(100.0 * medium / total + 0.5);
        int highPct = static_cast<int>(100.0 * high / total + 0.5);
        int criticalPct = static_cast<int>(100.0 * critical / total + 0.5);

        os << "  Total alerts        : " << total << "\n";
        os << "  By type             : SSH=" << sshAlerts_.size() << ", FW=" << fwAlerts_.size()
           << ", Correlated=" << correlatedAlerts_.size() << "\n";
        os << "  MEDIUM              : " << medium << " (" << mediumPct << "%) " << makeBar(mediumPct) << "\n";
        os << "  HIGH                : " << high << " (" << highPct << "%) " << makeBar(highPct) << "\n";
        os << "  CRITICAL            : " << critical << " (" << criticalPct << "%) " << makeBar(criticalPct) << "\n";
        os << "  Distinct IPs alerted: " << ips.size() << "\n";
        os << "  Most active attacker: " << ips[top] << " (" << counts[top] << " alerts)\n";
        if (events > 0) {
            os << "  Detection rate      : " << static_cast<int>(100.0 * total / events + 0.5) << " alerts per 100 events ("
               << total << " alerts / " << events << " events)\n";
        }
    }

    friend std::ostream& operator<<(std::ostream& os, const Analyzer& analyzer) {
        analyzer.printReport(os);
        return os;
    }
};

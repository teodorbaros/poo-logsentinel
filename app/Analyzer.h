#ifndef ANALYZER_H
#define ANALYZER_H

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include "Alert.h"
#include "DetectionPolicy.h"
#include "FirewallSource.h"
#include "IpList.h"
#include "IpTracker.h"
#include "LogSource.h"
#include "PortScanTracker.h"

// Motorul de detectie: brute-force SSH, port scan, corelare intre surse, IP-uri din blacklist.
// Lucreaza direct pe sursele si listele aplicatiei (referinte), deci nu mai tine copii care trebuie sincronizate.
class Analyzer {
private:
    const LogSource& sshSource_;
    const FirewallSource& fwSource_;
    const IpList& whitelist_;
    const IpList& blacklist_;
    DetectionPolicy policy_;
    std::vector<IpTracker> sshTrackers_;
    std::vector<PortScanTracker> fwTrackers_;
    std::vector<Alert> sshAlerts_;
    std::vector<Alert> fwAlerts_;
    std::vector<Alert> correlatedAlerts_;
    std::vector<Alert> blacklistAlerts_;

    // o singura alerta BLACKLIST-HIT per IP
    void recordBlacklistHit(const LogEntry& trigger, const std::string& sourceLabel) {
        if (!containsIp(blacklistAlerts_, trigger.getIpString())) {
            blacklistAlerts_.emplace_back("IP din blacklist", "a aparut in log-urile " + sourceLabel, trigger,
                                          Alert::kBlacklistScore);
        }
    }

    static bool containsIp(const std::vector<Alert>& alerts, const std::string& ip) {
        for (const Alert& alert : alerts) {
            if (alert.matchesIpString(ip)) {
                return true;
            }
        }
        return false;
    }


    static int printMatching(std::ostream& os, const std::vector<Alert>& alerts, const std::string& ip) {
        int count = 0;
        for (const Alert& alert : alerts) {
            if (alert.matchesIpString(ip)) {
                os << alert << "\n";
                count++;
            }
        }
        return count;
    }

    // Apare alerta in raport? Are severitatea ceruta si, cu `hideCorrelated`, IP-ul ei nu are deja o alerta
    // de atac in doua etape (detaliile ei sunt deja acolo).
    bool isReported(const Alert& alert, const std::string& severity, bool hideCorrelated) const {
        return alert.hasSeverity(severity) && !(hideCorrelated && containsIp(correlatedAlerts_, alert.getIpString()));
    }

    void printSeverity(std::ostream& os, const std::vector<Alert>& alerts, const std::string& severity,
                       bool hideCorrelated) const {
        for (const Alert& alert : alerts) {
            if (isReported(alert, severity, hideCorrelated)) {
                os << alert << "\n";
            }
        }
    }

    int countSeverity(const std::vector<Alert>& alerts, const std::string& severity, bool hideCorrelated) const {
        int count = 0;
        for (const Alert& alert : alerts) {
            count += isReported(alert, severity, hideCorrelated) ? 1 : 0;
        }
        return count;
    }

    // adauga in `result` alertele HIGH/CRITICAL ale caror IP nu e deja acolo
    static void addHighUniqueByIp(std::vector<Alert>& result, const std::vector<Alert>& alerts) {
        for (const Alert& alert : alerts) {
            if (alert.isHighOrCritical() && !containsIp(result, alert.getIpString())) {
                result.push_back(alert);
            }
        }
    }

    int findSshTracker(const LogEntry& entry) const {
        for (std::size_t i = 0; i < sshTrackers_.size(); i++) {
            if (sshTrackers_[i].tracksSameIp(entry)) {
                return static_cast<int>(i);
            }
        }
        return -1;
    }

    int findFwTracker(const FirewallEntry& packet) const {
        for (std::size_t i = 0; i < fwTrackers_.size(); i++) {
            if (fwTrackers_[i].tracksSameIp(packet)) {
                return static_cast<int>(i);
            }
        }
        return -1;
    }

    // Pentru fiecare incercare SSH: whitelist -> sarim; blacklist -> alerta imediata;
    // apoi contorul IP-ului; la prag -> alerta SSH-BRUTEFORCE si contorul se sterge
    int detectSshBruteForce() {
        sshTrackers_.clear();
        sshAlerts_.clear();
        for (int i = 0; i < sshSource_.getEntryCount(); i++) {
            const LogEntry& entry = sshSource_.getEntryAt(i);
            if (whitelist_.contains(entry.getAddress())) {
                continue;
            }
            if (blacklist_.contains(entry.getAddress())) {
                recordBlacklistHit(entry, "SSH");
            }
            int index = findSshTracker(entry);
            if (index < 0) {
                sshTrackers_.emplace_back(entry);
                index = static_cast<int>(sshTrackers_.size()) - 1;
            } else {
                sshTrackers_[static_cast<std::size_t>(index)].recordAttempt(entry, policy_);
            }
            if (sshTrackers_[static_cast<std::size_t>(index)].isAttack(policy_)) {
                sshAlerts_.push_back(sshTrackers_[static_cast<std::size_t>(index)].createAlert(entry));
                sshTrackers_.erase(sshTrackers_.begin() + index);
            }
        }
        return static_cast<int>(sshAlerts_.size());
    }

    // La fel, pentru pachetele firewall (alerta FW-PORTSCAN)
    int detectFirewallPortScans() {
        fwTrackers_.clear();
        fwAlerts_.clear();
        for (int i = 0; i < fwSource_.getEntryCount(); i++) {
            const FirewallEntry& packet = fwSource_.getEntryAt(i);
            if (whitelist_.contains(packet.getAddress())) {
                continue;
            }
            if (blacklist_.contains(packet.getAddress())) {
                recordBlacklistHit(packet.toTriggerEntry(), "firewall");
            }
            int index = findFwTracker(packet);
            if (index < 0) {
                fwTrackers_.emplace_back(packet);
                index = static_cast<int>(fwTrackers_.size()) - 1;
            } else {
                fwTrackers_[static_cast<std::size_t>(index)].recordPacket(packet, policy_);
            }
            if (fwTrackers_[static_cast<std::size_t>(index)].isPortScan(policy_)) {
                fwAlerts_.push_back(fwTrackers_[static_cast<std::size_t>(index)].createScanAlert(packet));
                fwTrackers_.erase(fwTrackers_.begin() + index);
            }
        }
        return static_cast<int>(fwAlerts_.size());
    }

    // Port scan + brute-force de la acelasi IP = atac in mai multe etape.
    // O singura alerta per IP (inainte iesea cate una pentru fiecare pereche de alerte).
    int correlateMultiStageAttacks() {
        correlatedAlerts_.clear();
        for (const Alert& scan : fwAlerts_) {
            if (containsIp(correlatedAlerts_, scan.getIpString())) {
                continue;
            }
            for (const Alert& bruteForce : sshAlerts_) {
                if (scan.involvesSameIpAs(bruteForce)) {
                    correlatedAlerts_.push_back(scan.promoteToCorrelatedAlert(bruteForce));
                    break;
                }
            }
        }
        return static_cast<int>(correlatedAlerts_.size());
    }

public:
    Analyzer(const LogSource& sshSource, const FirewallSource& fwSource, const IpList& whitelist,
             const IpList& blacklist)
        : sshSource_(sshSource), fwSource_(fwSource), whitelist_(whitelist), blacklist_(blacklist) {}

    const DetectionPolicy& getPolicy() const { return policy_; }

    // false daca politica noua e invalida (atunci o pastram pe cea veche)
    bool updatePolicy(const DetectionPolicy& policy) {
        if (!policy.isValid()) {
            return false;
        }
        policy_ = policy;
        return true;
    }

    // scanarea completa; intoarce numarul total de alerte
    int runFullSiemAnalysis() {
        blacklistAlerts_.clear();
        const int total = detectSshBruteForce() + detectFirewallPortScans() + correlateMultiStageAttacks();
        return total + static_cast<int>(blacklistAlerts_.size());
    }

    // cate alerte apar in raport cu severitatea data (dupa ce atacurile in doua etape le-au inglobat pe celelalte)
    int countReported(const std::string& severity) const {
        return countSeverity(correlatedAlerts_, severity, false) + countSeverity(blacklistAlerts_, severity, false) +
               countSeverity(sshAlerts_, severity, true) + countSeverity(fwAlerts_, severity, true);
    }


    // candidatii pentru blacklist: cate o alerta HIGH/CRITICAL per IP, cele corelate primele
    std::vector<Alert> getHighRiskAlertsUniqueByIp() const {
        std::vector<Alert> result;
        addHighUniqueByIp(result, correlatedAlerts_);
        addHighUniqueByIp(result, sshAlerts_);
        addHighUniqueByIp(result, fwAlerts_);
        return result;
    }

    int printAlertsForIp(std::ostream& os, const std::string& ip) const {
        return printMatching(os, blacklistAlerts_, ip) + printMatching(os, correlatedAlerts_, ip) +
               printMatching(os, sshAlerts_, ip) + printMatching(os, fwAlerts_, ip);
    }

    bool hasAnyAlerts() const {
        return !correlatedAlerts_.empty() || !blacklistAlerts_.empty() || !sshAlerts_.empty() || !fwAlerts_.empty();
    }

    // ordinea prioritatii: corelate, blacklist, SSH, firewall (apelata doar daca hasAnyAlerts())
    Alert getTopPriorityAlert() const {
        if (!correlatedAlerts_.empty()) {
            return correlatedAlerts_.front();
        }
        if (!blacklistAlerts_.empty()) {
            return blacklistAlerts_.front();
        }
        if (!sshAlerts_.empty()) {
            return sshAlerts_.front();
        }
        return fwAlerts_.front();
    }

    // IP-urile cu activitate suspecta care n-au atins pragul (merita urmarite)
    void printActiveTrackers(std::ostream& os) const {
        std::ostringstream lines;
        for (const IpTracker& tracker : sshTrackers_) {
            if (tracker.hasFailures()) {
                lines << "  " << tracker << "\n";
            }
        }
        for (const PortScanTracker& tracker : fwTrackers_) {
            if (tracker.hasBlockedPorts()) {
                lines << "  " << tracker << "\n";
            }
        }
        if (!lines.str().empty()) {
            os << "\nActivitate sub prag, de urmarit:\n" << lines.str();
        }
    }

    // Raportul: cele mai grave primele. Un IP cu atac in doua etape apare o singura data.
    friend std::ostream& operator<<(std::ostream& os, const Analyzer& analyzer) {
        if (!analyzer.hasAnyAlerts()) {
            return os << "Niciun IP n-a depasit pragurile.\n";
        }
        for (const char* severity : {"CRITICAL", "HIGH", "MEDIUM"}) {
            analyzer.printSeverity(os, analyzer.correlatedAlerts_, severity, false);
            analyzer.printSeverity(os, analyzer.blacklistAlerts_, severity, false);
            analyzer.printSeverity(os, analyzer.sshAlerts_, severity, true);
            analyzer.printSeverity(os, analyzer.fwAlerts_, severity, true);
        }
        return os;
    }
};

#endif

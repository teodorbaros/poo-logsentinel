#ifndef SIEM_CONSOLE_APP_HPP
#define SIEM_CONSOLE_APP_HPP

#include <iostream>
#include <fstream>
#include <vector>
#include "LogSource.hpp"
#include "FirewallSource.hpp"
#include "Analyzer.hpp"
#include "Alert.hpp"

class SiemConsoleApp {
private:
    LogSource sshSource_;
    FirewallSource fwSource_;
    Analyzer analyzer_;
    std::vector<Alert> archivedAlerts_;

    void printMenuHeader() const {
        std::cout << "\n=========================================================\n";
        std::cout << "              LOGSENTINEL SIEM CONSOLE MENU               \n";
        std::cout << "              Archived Incidents: " << archivedAlerts_.size() << "\n";
        std::cout << "=========================================================\n";
        std::cout << " [1] Ingest SSH authentication logs from input\n";
        std::cout << " [2] Ingest Firewall packet logs from input\n";
        std::cout << " [3] Update SIEM detection policy thresholds\n";
        std::cout << " [4] Run full SIEM correlation scan & view report\n";
        std::cout << " [5] Investigate specific IP address activity\n";
        std::cout << " [6] Archive & escalate top priority alert\n";
        std::cout << " [0] Exit application\n";
        std::cout << "Select option: ";
    }

    void handleSshIngestion(std::istream& in) {
        int lineCount = 0;
        if (!(in >> lineCount) || lineCount <= 0) {
            return;
        }
        sshSource_.ingestFromStream(in, lineCount);
        analyzer_.syncSources(sshSource_, fwSource_);
        std::cout << "\nUpdated " << sshSource_ << "\n";
    }

    void handleFirewallIngestion(std::istream& in) {
        int packetCount = 0;
        if (!(in >> packetCount) || packetCount <= 0) {
            return;
        }
        fwSource_.ingestFromStream(in, packetCount);
        analyzer_.syncSources(sshSource_, fwSource_);
        std::cout << "\nUpdated " << fwSource_ << "\n";
    }

    void handlePolicyUpdate(std::istream& in) {
        int sshThresh = 5;
        int fwThresh = 4;
        int windowSec = 60;
        double ratio = 0.8;

        if (in >> sshThresh >> fwThresh >> windowSec >> ratio) {
            analyzer_.updatePolicy(sshThresh, fwThresh, windowSec, ratio);
            std::cout << "\nSIEM Policy updated: SSH Threshold=" << sshThresh
                      << ", FW Port Threshold=" << fwThresh
                      << ", Window=" << windowSec << "s"
                      << ", MinFailureRatio=" << ratio << "\n";
        }
    }

    void handleFullScan() {
        analyzer_.syncSources(sshSource_, fwSource_);
        int totalAlerts = analyzer_.runFullSiemAnalysis();
        int highSeverity = analyzer_.countHighSeverityIncidents();

        std::cout << "\n=== SIEM Scan Completed: " << totalAlerts
                  << " alerts (" << highSeverity << " HIGH/CRITICAL) ===\n";
        std::cout << analyzer_;
        analyzer_.printActiveTrackers(std::cout);
    }

    void handleIpInvestigation(std::istream& in) const {
        std::string targetIp;
        if (!(in >> targetIp)) {
            return;
        }
        std::cout << "\n=== Threat Intelligence Report for IP: " << targetIp << " ===\n";
        std::cout << "SSH Activity:\n";
        int sshHits = sshSource_.printEntriesForIp(std::cout, targetIp);
        std::cout << "Firewall Activity:\n";
        int fwHits = fwSource_.printPacketsForIp(std::cout, targetIp);

        if (sshHits > 0 && fwHits > 0 && sshSource_.getEntryCount() > 0 && fwSource_.getEntryCount() > 0) {
            const LogEntry& sampleSsh = sshSource_.getEntryAt(0);
            const FirewallEntry& sampleFw = fwSource_.getEntryAt(0);
            if (sampleFw.matchesLogEntryIp(sampleSsh)) {
                std::cout << "Cross-check confirmed: Primary SSH & FW entries share source IP.\n";
            }
        }

        std::cout << "Triggered Alerts for " << targetIp << ":\n";
        analyzer_.printAlertsForIp(std::cout, targetIp);
    }

    void handleAlertArchival() {
        if (!analyzer_.hasAnyAlerts()) {
            std::cout << "\nNo active alerts available to archive.\n";
            return;
        }

        Alert topAlert = analyzer_.getTopPriorityAlert();
        Alert snapshotCopy(topAlert);

        if (sshSource_.getEntryCount() > 0) {
            Alert escalatedAlert("SOC-ESCALATION", "Incident assigned to Tier-2 Blue Team responder",
                                 sshSource_.getEntryAt(0), 9);
            topAlert = escalatedAlert;
        }

        archivedAlerts_.push_back(snapshotCopy);
        archivedAlerts_.push_back(topAlert);

        std::cout << "\n=== Incident Archival & Escalation ===\n";
        std::cout << "Archived Snapshot:  " << snapshotCopy << "\n";
        std::cout << "Escalated Incident: " << topAlert << "\n";
    }

public:
    SiemConsoleApp(const std::string& sshFile, const std::string& fwFile)
        : sshSource_(sshFile),
          fwSource_(fwFile),
          analyzer_(sshSource_, fwSource_, 5, 4, 60, 0.8) {
        std::ofstream clearSsh(sshFile, std::ios::trunc);
        std::ofstream clearFw(fwFile, std::ios::trunc);
        sshSource_.loadFromFile();
        fwSource_.loadFromFile();
    }

    void run(std::istream& in) {
        int option = -1;
        while (true) {
            printMenuHeader();
            if (!(in >> option)) {
                std::cout << "\nInput stream closed. Exiting LogSentinel SIEM.\n";
                break;
            }

            if (option == 0) {
                std::cout << "\nShutting down LogSentinel SIEM Console.\n";
                break;
            } else if (option == 1) {
                handleSshIngestion(in);
            } else if (option == 2) {
                handleFirewallIngestion(in);
            } else if (option == 3) {
                handlePolicyUpdate(in);
            } else if (option == 4) {
                handleFullScan();
            } else if (option == 5) {
                handleIpInvestigation(in);
            } else if (option == 6) {
                handleAlertArchival();
            } else {
                std::cout << "\nUnknown command code: " << option << "\n";
            }
        }
    }

    friend std::ostream& operator<<(std::ostream& os, const SiemConsoleApp& app) {
        os << app.sshSource_ << "\n" << app.fwSource_
           << "\nArchived Incidents: " << app.archivedAlerts_.size();
        return os;
    }
};

#endif // SIEM_CONSOLE_APP_HPP

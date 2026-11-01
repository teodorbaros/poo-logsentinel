#pragma once
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "Alert.hpp"
#include "Analyzer.hpp"
#include "FirewallSource.hpp"
#include "LogSource.hpp"

class SiemConsoleApp {
private:
    LogSource sshSource_;
    FirewallSource fwSource_;
    Analyzer analyzer_;
    std::vector<Alert> archivedAlerts_;

    void printMenuHeader() const {
        std::cout << "\n=========================================================\n";
        std::cout << "             LOGSENTINEL SIEM CONSOLE MENU               \n";
        std::cout << "=========================================================\n";
        std::cout << " SSH entries loaded      : " << sshSource_.getEntryCount() << "\n";
        std::cout << " Firewall packets loaded : " << fwSource_.getEntryCount() << "\n";
        std::cout << " Archived incidents      : " << archivedAlerts_.size() << "\n";
        std::cout << "---------------------------------------------------------\n";
        std::cout << " [1] Ingest SSH authentication logs from input\n";
        std::cout << " [2] Ingest Firewall packet logs from input\n";
        std::cout << " [3] Update SIEM detection policy thresholds\n";
        std::cout << " [4] Run full SIEM correlation scan & view report\n";
        std::cout << " [5] Investigate specific IP address activity\n";
        std::cout << " [6] Archive & escalate top priority alert\n";
        std::cout << " [7] View session statistics & rates\n";
        std::cout << " [0] Exit application\n";
        std::cout << "---------------------------------------------------------\n";
        std::cout << "Select option: ";
    }

    void handleSshIngestion(std::istream& in) {
        int lineCount = 0;
        if (!(in >> lineCount) || lineCount <= 0) {
            std::cout << "\n[!] Invalid line count, SSH ingestion cancelled.\n";
            return;
        }
        std::cout << "\n>>> Ingesting " << lineCount << " SSH log lines...\n";
        std::size_t before = sshSource_.getEntryCount();
        sshSource_.ingestFromStream(in, lineCount);
        analyzer_.syncSources(sshSource_, fwSource_);
        std::cout << ">>> Ingestion finished. New valid entries: "
                  << (sshSource_.getEntryCount() - before) << "\n";
        std::cout << "\nUpdated " << sshSource_ << "\n";
    }

    void handleFirewallIngestion(std::istream& in) {
        int packetCount = 0;
        if (!(in >> packetCount) || packetCount <= 0) {
            std::cout << "\n[!] Invalid packet count, firewall ingestion cancelled.\n";
            return;
        }
        std::cout << "\n>>> Ingesting " << packetCount << " firewall packets...\n";
        std::size_t before = fwSource_.getEntryCount();
        fwSource_.ingestFromStream(in, packetCount);
        analyzer_.syncSources(sshSource_, fwSource_);
        std::cout << ">>> Ingestion finished. New valid packets: "
                  << (fwSource_.getEntryCount() - before) << "\n";
        std::cout << "\nUpdated " << fwSource_ << "\n";
    }

    void handlePolicyUpdate(std::istream& in) {
        int sshThresh = 5;
        int fwThresh = 4;
        int windowSec = 60;
        double ratio = 0.8;

        if (in >> sshThresh >> fwThresh >> windowSec >> ratio) {
            analyzer_.updatePolicy(sshThresh, fwThresh, windowSec, ratio);
            std::cout << "\n=== SIEM Policy Updated ===\n";
            std::cout << "  SSH failure threshold : " << sshThresh << "\n";
            std::cout << "  FW port threshold     : " << fwThresh << " distinct ports\n";
            std::cout << "  Time window           : " << windowSec << "s\n";
            std::cout << "  Min failure ratio     : " << ratio << "\n";
            std::cout << "  (values <= 0 are ignored and the old value is kept)\n";
        } else {
            std::cout << "\n[!] Invalid policy values, nothing changed.\n";
        }
    }

    void handleFullScan() {
        std::cout << "\n>>> Starting full SIEM scan...\n";
        std::cout << ">>> Analyzing " << sshSource_.getEntryCount() << " SSH entries and "
                  << fwSource_.getEntryCount() << " firewall packets\n";
        analyzer_.syncSources(sshSource_, fwSource_);
        int totalAlerts = analyzer_.runFullSiemAnalysis();
        int highSeverity = analyzer_.countHighSeverityIncidents();

        std::cout << "\n=== SIEM Scan Completed ===\n";
        std::cout << "  Total alerts        : " << totalAlerts << "\n";
        std::cout << "  HIGH/CRITICAL       : " << highSeverity << "\n";
        std::cout << "  Lower severity      : " << (totalAlerts - highSeverity) << "\n";
        std::cout << analyzer_;
        analyzer_.printActiveTrackers(std::cout);
        std::cout << "\n";
        analyzer_.printStatistics(std::cout);
    }

    void handleIpInvestigation(std::istream& in) const {
        std::string targetIp;
        if (!(in >> targetIp)) {
            std::cout << "\n[!] No IP address provided.\n";
            return;
        }
        std::cout << "\n=========================================================\n";
        std::cout << "  Threat Intelligence Report for IP: " << targetIp << "\n";
        std::cout << "=========================================================\n";
        std::cout << "SSH Activity:\n";
        int sshHits = sshSource_.printEntriesForIp(std::cout, targetIp);
        std::cout << "  -> " << sshHits << " SSH entries found\n";
        std::cout << "Firewall Activity:\n";
        int fwHits = fwSource_.printPacketsForIp(std::cout, targetIp);
        std::cout << "  -> " << fwHits << " firewall packets found\n";

        if (sshHits > 0 && fwHits > 0 && sshSource_.getEntryCount() > 0 && fwSource_.getEntryCount() > 0) {
            const LogEntry& sampleSsh = sshSource_.getEntryAt(0);
            const FirewallEntry& sampleFw = fwSource_.getEntryAt(0);
            if (sampleFw.matchesLogEntryIp(sampleSsh)) {
                std::cout << "Cross-check confirmed: Primary SSH & FW entries share source IP.\n";
            }
        }

        std::cout << "Triggered Alerts for " << targetIp << ":\n";
        analyzer_.printAlertsForIp(std::cout, targetIp);
        std::cout << "---------------------------------------------------------\n";
    }

    void handleAlertArchival() {
        if (!analyzer_.hasAnyAlerts()) {
            std::cout << "\nNo active alerts available to archive.\n";
            std::cout << "Hint: run option [4] first to generate alerts.\n";
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
        std::cout << "Step 1: Selected top priority alert\n";
        std::cout << "Step 2: Created snapshot copy (copy constructor)\n";
        std::cout << "Step 3: Replaced working alert with escalation (operator=)\n";
        std::cout << "\nArchived Snapshot:\n  " << snapshotCopy << "\n";
        std::cout << "\nEscalated Incident:\n  " << topAlert << "\n";
        std::cout << "\nArchive now holds " << archivedAlerts_.size() << " incidents.\n";
    }

    void handleStatistics() const {
        std::cout << "\n=========================================================\n";
        std::cout << "                 SESSION STATISTICS                      \n";
        std::cout << "=========================================================\n";
        sshSource_.printStatistics(std::cout);
        std::cout << "\n";
        fwSource_.printStatistics(std::cout);
        std::cout << "\n";
        analyzer_.printStatistics(std::cout);
        std::cout << "---------------------------------------------------------\n";
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
                std::cout << "\n[i] Input stream closed. Exiting LogSentinel SIEM.\n";
                break;
            }

            if (option == 0) {
                std::cout << "\n>>> Shutting down LogSentinel SIEM Console.\n";
                std::cout << ">>> Goodbye!\n";
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
            } else if (option == 7) {
                handleStatistics();
            } else {
                std::cout << "\n[!] Unknown command code: " << option << "\n";
                std::cout << "[!] Valid options are 0-7.\n";
            }
        }
    }

    friend std::ostream& operator<<(std::ostream& os, const SiemConsoleApp& app) {
        os << app.sshSource_ << "\n" << app.fwSource_
           << "\n[Archive]\n    Archived incidents : " << app.archivedAlerts_.size();
        return os;
    }
};

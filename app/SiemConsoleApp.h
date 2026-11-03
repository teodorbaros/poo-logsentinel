#ifndef SIEM_CONSOLE_APP_H
#define SIEM_CONSOLE_APP_H

#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include "LogSource.h"
#include "FirewallSource.h"
#include "Analyzer.h"
#include "Alert.h"

class SiemConsoleApp {
private:
    LogSource sshSource_;
    FirewallSource fwSource_;
    Analyzer analyzer_;
    std::vector<Alert> archivedAlerts_;
    int executedCommands_;
    int currentSshThreshold_;
    int currentFwThreshold_;
    int currentWindowSeconds_;
    double currentMinRatio_;

    void printStartupBanner() const {
        std::cout << "+====================================================================+\n";
        std::cout << "|                 LOGSENTINEL SIEM - BLUE TEAM CONSOLE               |\n";
        std::cout << "|        Real-Time SSH & Firewall Threat Correlation Engine          |\n";
        std::cout << "+====================================================================+\n";
        std::cout << "| Initialized SSH Stream : " << sshSource_ << "\n";
        std::cout << "| Initialized FW  Stream : " << fwSource_ << "\n";
        std::cout << "+====================================================================+\n";
    }

    void printMenuHeader() const {
        std::cout << "\n+--------------------------------------------------------------------+\n";
        std::cout << "|                    LOGSENTINEL SIEM CONSOLE MENU                   |\n";
        std::cout << "+--------------------------------------------------------------------+\n";
        std::cout << "| Session Commands Run : " << executedCommands_
                  << " | Archived SOC Incidents : " << archivedAlerts_.size() << "\n";
        std::cout << "| Active Policy        : SSH >= " << currentSshThreshold_
                  << " | FW Ports >= " << currentFwThreshold_
                  << " | Window: " << currentWindowSeconds_ << "s\n";
        std::cout << "+--------------------------------------------------------------------+\n";
        std::cout << "|  [1] Ingest SSH authentication logs from input stream              |\n";
        std::cout << "|  [2] Ingest Firewall packet logs from input stream                 |\n";
        std::cout << "|  [3] Update SIEM detection policy thresholds                       |\n";
        std::cout << "|  [4] Run full SIEM correlation scan & view executive report        |\n";
        std::cout << "|  [5] Investigate specific IP address activity (Threat Intel)       |\n";
        std::cout << "|  [6] Archive & escalate top priority alert to Tier-2 SOC           |\n";
        std::cout << "|  [7] Display SIEM telemetry, audit log & archived incidents        |\n";
        std::cout << "|  [8] Load SSH / Firewall logs from a file path (ssh|fw <path>)       |\n";
        std::cout << "|  [0] Exit application and generate session summary                 |\n";
        std::cout << "+--------------------------------------------------------------------+\n";
        std::cout << "Select option >> ";
    }

    void handleSshIngestion(std::istream& in) {
        int lineCount = 0;
        if (!(in >> lineCount) || lineCount <= 0) {
            return;
        }
        std::cout << "\n[INGEST] Reading " << lineCount << " SSH records from input stream...\n";
        sshSource_.ingestFromStream(in, lineCount);
        analyzer_.syncSources(sshSource_, fwSource_);
        std::cout << "[OK] Updated " << sshSource_ << "\n";
    }

    void handleFirewallIngestion(std::istream& in) {
        int packetCount = 0;
        if (!(in >> packetCount) || packetCount <= 0) {
            return;
        }
        std::cout << "\n[INGEST] Reading " << packetCount << " Firewall packets from input stream...\n";
        fwSource_.ingestFromStream(in, packetCount);
        analyzer_.syncSources(sshSource_, fwSource_);
        std::cout << "[OK] Updated " << fwSource_ << "\n";
    }

    void handleFileIngestion(std::istream& in) {
        std::string sourceType;
        std::string path;
        if (!(in >> sourceType >> path)) {
            return;
        }
        if (sourceType != "ssh" && sourceType != "fw") {
            std::cout << "\n[ERROR] Unknown source type '" << sourceType << "' (expected: ssh or fw)\n";
            return;
        }

        std::ifstream file(path);
        if (!file.is_open()) {
            std::cout << "\n[ERROR] Cannot open log file: " << path << "\n";
            return;
        }

        std::cout << "\n[INGEST] Loading " << sourceType << " records from file " << path << "...\n";
        int recordsRead = 0;
        if (sourceType == "ssh") {
            recordsRead = sshSource_.ingestUntilEof(file);
        } else {
            recordsRead = fwSource_.ingestUntilEof(file);
        }

        if (!file.eof()) {
            std::cout << "[WARN] Reading stopped early: malformed line in " << path << "\n";
        }
        if (recordsRead == 0) {
            std::cout << "[WARN] No readable records found in " << path << " (empty file or wrong format).\n";
            return;
        }

        analyzer_.syncSources(sshSource_, fwSource_);
        std::cout << "[OK] Read " << recordsRead << " records. Updated ";
        if (sourceType == "ssh") {
            std::cout << sshSource_ << "\n";
        } else {
            std::cout << fwSource_ << "\n";
        }
    }

    void handlePolicyUpdate(std::istream& in) {
        int sshThresh = 5;
        int fwThresh = 4;
        int windowSec = 60;
        double ratio = 0.8;

        if (in >> sshThresh >> fwThresh >> windowSec >> ratio) {
            currentSshThreshold_ = sshThresh;
            currentFwThreshold_ = fwThresh;
            currentWindowSeconds_ = windowSec;
            currentMinRatio_ = ratio;
            analyzer_.updatePolicy(sshThresh, fwThresh, windowSec, ratio);

            std::cout << "\n+--------------------------------------------------------------------+\n";
            std::cout << "|                  SIEM DETECTION POLICY UPDATED                     |\n";
            std::cout << "+--------------------------------------------------------------------+\n";
            std::cout << "|  * SSH Brute-Force Threshold : " << currentSshThreshold_ << " failed attempts\n";
            std::cout << "|  * Firewall Port Scan Limit  : " << currentFwThreshold_ << " distinct ports\n";
            std::cout << "|  * Correlation Time Window   : " << currentWindowSeconds_ << " seconds\n";
            std::cout << "|  * Minimum Failure Ratio     : " << currentMinRatio_ << "\n";
            std::cout << "+--------------------------------------------------------------------+\n";
        }
    }

    void handleFullScan() {
        analyzer_.syncSources(sshSource_, fwSource_);
        int totalAlerts = analyzer_.runFullSiemAnalysis();
        int highSeverity = analyzer_.countHighSeverityIncidents();

        std::cout << "\n+====================================================================+\n";
        std::cout << "|                 SIEM CORRELATION SCAN EXECUTIVE REPORT             |\n";
        std::cout << "+====================================================================+\n";
        std::cout << "| Total Detected Incidents : " << totalAlerts << "\n";
        std::cout << "| High / Critical Alerts   : " << highSeverity << "\n";
        std::cout << "+--------------------------------------------------------------------+\n";
        std::cout << analyzer_;
        std::cout << "+--------------------------------------------------------------------+\n";
        analyzer_.printActiveTrackers(std::cout);
        std::cout << "+====================================================================+\n";
    }

    void handleIpInvestigation(std::istream& in) const {
        std::string targetIp;
        if (!(in >> targetIp)) {
            return;
        }
        std::cout << "\n+====================================================================+\n";
        std::cout << "|  THREAT INTELLIGENCE & FORENSIC REPORT FOR IP: " << targetIp << "\n";
        std::cout << "+====================================================================+\n";
        std::cout << "[1] Recorded SSH Authentication Events:\n";
        int sshHits = sshSource_.printEntriesForIp(std::cout, targetIp);
        if (sshHits == 0) {
            std::cout << "  (No SSH events recorded for this IP)\n";
        }

        std::cout << "[2] Recorded Firewall Packet Events:\n";
        int fwHits = fwSource_.printPacketsForIp(std::cout, targetIp);
        if (fwHits == 0) {
            std::cout << "  (No Firewall packets recorded for this IP)\n";
        }

        if (sshHits > 0 && fwHits > 0 && sshSource_.getEntryCount() > 0 && fwSource_.getEntryCount() > 0) {
            const LogEntry& sampleSsh = sshSource_.getEntryAt(0);
            const FirewallEntry& sampleFw = fwSource_.getEntryAt(0);
            if (sampleFw.matchesLogEntryIp(sampleSsh)) {
                std::cout << "[!] Cross-Source Match: Primary SSH & Firewall records share source IP.\n";
            }
        }

        std::cout << "[3] Triggered SIEM Alerts for " << targetIp << ":\n";
        analyzer_.printAlertsForIp(std::cout, targetIp);
        std::cout << "+====================================================================+\n";
    }

    void handleAlertArchival() {
        if (!analyzer_.hasAnyAlerts()) {
            std::cout << "\n[WARN] No active alerts available to archive.\n";
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

        std::cout << "\n+--------------------------------------------------------------------+\n";
        std::cout << "|                 INCIDENT ARCHIVAL & SOC ESCALATION                 |\n";
        std::cout << "+--------------------------------------------------------------------+\n";
        std::cout << "| Archived Snapshot  : " << snapshotCopy << "\n";
        std::cout << "| Escalated Incident : " << topAlert << "\n";
        std::cout << "+--------------------------------------------------------------------+\n";
    }

    void handleTelemetryAndAudit() const {
        std::cout << "\n+====================================================================+\n";
        std::cout << "|               SIEM TELEMETRY & ARCHIVED INCIDENT VAULT             |\n";
        std::cout << "+====================================================================+\n";
        std::cout << "| " << sshSource_ << "\n";
        std::cout << "| " << fwSource_ << "\n";
        std::cout << "| Total Console Operations Executed : " << executedCommands_ << "\n";
        std::cout << "+--------------------------------------------------------------------+\n";
        std::cout << "| Vault Incidents (" << archivedAlerts_.size() << "):\n";
        for (std::size_t i = 0; i < archivedAlerts_.size(); i++) {
            std::cout << "|   #" << (i + 1) << " -> " << archivedAlerts_[i] << "\n";
        }
        std::cout << "+====================================================================+\n";
    }

public:
    SiemConsoleApp(const std::string& sshStreamName, const std::string& fwStreamName)
        : sshSource_(sshStreamName),
          fwSource_(fwStreamName),
          analyzer_(sshSource_, fwSource_, 5, 4, 60, 0.8),
          executedCommands_(0),
          currentSshThreshold_(5),
          currentFwThreshold_(4),
          currentWindowSeconds_(60),
          currentMinRatio_(0.8) {}

    void run(std::istream& in) {
        printStartupBanner();
        int option = -1;
        while (true) {
            printMenuHeader();
            if (!(in >> option)) {
                std::cout << "\n[INFO] Input stream closed. Exiting LogSentinel SIEM.\n";
                break;
            }

            executedCommands_++;

            if (option == 0) {
                std::cout << "\n[SHUTDOWN] Closing LogSentinel SIEM Console...\n";
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
                handleTelemetryAndAudit();
            } else if (option == 8) {
                handleFileIngestion(in);
            } else {
                std::cout << "\n[ERROR] Unknown command code: " << option << "\n";
            }
        }
    }

    friend std::ostream& operator<<(std::ostream& os, const SiemConsoleApp& app) {
        os << "+====================================================================+\n"
           << "|                      FINAL SIEM SESSION SUMMARY                    |\n"
           << "+====================================================================+\n"
           << "| " << app.sshSource_ << "\n"
           << "| " << app.fwSource_ << "\n"
           << "| Commands Executed  : " << app.executedCommands_ << "\n"
           << "| Archived Incidents : " << app.archivedAlerts_.size() << "\n"
           << "+====================================================================+";
        return os;
    }
};

#endif

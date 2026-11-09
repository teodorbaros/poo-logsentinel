#ifndef ALERT_H
#define ALERT_H

#include <iomanip>
#include <iostream>
#include <string>
#include "LogEntry.h"

// O alerta: ce s-a intamplat (tipul + detaliile), cat de grav e si evenimentul care a declansat-o.
// Clasa cu constructor de copiere, operator= si destructor (cerinta Temei 1):
//   - copierea e folosita la arhivare (pastram o copie a alertei originale)
//   - operator= e folosit cand inlocuim alerta cu versiunea ei escaladata
class Alert {
private:
    static constexpr int kCriticalScore = 8;
    static constexpr int kHighScore = 5;
    static constexpr int kSeverityColumn = 9;
    static constexpr int kIpColumn = 16;

    std::string kind_;       // "brute-force SSH", "port scan", ...
    std::string severity_;   // MEDIUM / HIGH / CRITICAL
    std::string details_;    // "6 parole gresite din 6 incercari in 23 s"
    LogEntry trigger_;       // momentul si IP-ul

    // scorul de risc -> severitate (scorul nu se pastreaza, doar eticheta)
    static std::string severityFor(int riskScore) {
        if (riskScore >= kCriticalScore) {
            return "CRITICAL";
        }
        if (riskScore >= kHighScore) {
            return "HIGH";
        }
        return "MEDIUM";
    }

public:
    // scoruri fixe pentru alertele care nu vin dintr-un contor
    static constexpr int kCorrelationScore = 10;
    static constexpr int kEscalationScore = 9;
    static constexpr int kBlacklistScore = 7;

    Alert(const std::string& kind, const std::string& details, const LogEntry& trigger, int riskScore)
        : kind_(kind), severity_(severityFor(riskScore)), details_(details), trigger_(trigger) {}

    Alert(const Alert& other)
        : kind_(other.kind_), severity_(other.severity_), details_(other.details_), trigger_(other.trigger_) {}

    Alert& operator=(const Alert& other) {
        if (this != &other) {
            kind_ = other.kind_;
            severity_ = other.severity_;
            details_ = other.details_;
            trigger_ = other.trigger_;
        }
        return *this;
    }

    ~Alert() = default;   // membrii (string, LogEntry) se elibereaza singuri

    bool hasSeverity(const std::string& severity) const { return severity_ == severity; }
    bool isHighOrCritical() const { return severity_ == "HIGH" || severity_ == "CRITICAL"; }
    bool involvesSameIpAs(const Alert& other) const { return trigger_.hasSameIp(other.trigger_); }
    bool matchesIpString(const std::string& targetIp) const { return trigger_.matchesIpString(targetIp); }
    const std::string& getIpString() const { return trigger_.getIpString(); }

    // "CRITICAL, atac in doua etape" - motivul trecut in blacklist dupa scan
    std::string reason() const { return severity_ + ", " + kind_; }

    // Port scan + brute-force de la acelasi IP -> un singur atac in doua etape
    Alert promoteToCorrelatedAlert(const Alert& secondStage) const {
        const std::string details = kind_ + " (" + details_ + "), apoi " + secondStage.kind_ + " (" +
                                    secondStage.details_ + ")";
        return {"atac in doua etape", details, secondStage.trigger_, kCorrelationScore};
    }

    // Aceeasi alerta, predata echipei Tier-2 (acelasi IP si moment, nu alt eveniment)
    Alert escalatedToTier2() const {
        return {"predat echipei Tier-2", kind_ + ": " + details_, trigger_, kEscalationScore};
    }

    //   CRITICAL 192.168.1.50     atac in doua etape, Oct 12 14:03:01
    //            port scan (5 porturi ...), apoi brute-force SSH (5 parole ...)
    friend std::ostream& operator<<(std::ostream& os, const Alert& alert) {
        return os << "  " << std::left << std::setw(kSeverityColumn) << alert.severity_ << std::setw(kIpColumn)
                  << alert.getIpString() << std::right << alert.kind_ << ", " << alert.trigger_.getTimestamp() << "\n"
                  << "  " << std::setw(kSeverityColumn) << "" << alert.details_;
    }
};

#endif

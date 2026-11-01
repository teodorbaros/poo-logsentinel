#pragma once

#include <ostream>
#include <string>
#include <vector>

#include "LogEntry.hpp"

class Alert {
private:
    std::string category_;
    std::string severity_;
    std::string message_;
    LogEntry trigger_;

    static std::string computeSeverityLabel(int score) {
        if (score >= 8) {
            return "CRITICAL";
        }
        if (score >= 5) {
            return "HIGH";
        }
        return "MEDIUM";
    }

public:
    Alert(const std::string& category, const std::string& message, const LogEntry& trigger, int riskScore = 5)
        : category_(category), severity_(computeSeverityLabel(riskScore)), message_(message), trigger_(trigger) {}

    Alert(const Alert& other)
        : category_(other.category_), severity_(other.severity_), message_(other.message_), trigger_(other.trigger_) {}

    Alert& operator=(const Alert& other) {
        if (this != &other) {
            category_ = other.category_;
            severity_ = other.severity_;
            message_ = other.message_;
            trigger_ = other.trigger_;
        }
        return *this;
    }

    ~Alert() {
        if (!message_.empty()) {
            message_.clear();
        }
        if (!category_.empty()) {
            category_.clear();
        }
        if (!severity_.empty()) {
            severity_.clear();
        }
    }

    bool isHighOrCritical() const {
        return severity_ == "HIGH" || severity_ == "CRITICAL";
    }

    bool involvesSameIpAs(const Alert& other) const {
        return trigger_.hasSameIp(other.trigger_);
    }

    bool matchesIpString(const std::string& targetIp) const {
        return trigger_.matchesIpString(targetIp);
    }

    void updateAlertStats(int& medium, int& high, int& critical,
                          std::vector<std::string>& ips, std::vector<int>& counts) const {
        if (severity_ == "CRITICAL") {
            critical++;
        } else if (severity_ == "HIGH") {
            high++;
        } else {
            medium++;
        }
        trigger_.countIp(ips, counts);
    }

    Alert promoteToCorrelatedAlert(const Alert& secondStage) const {
        std::string combinedMsg = "Multi-stage attack: Stage 1 (" + category_ + ": " + message_
                                + ") -> Stage 2 (" + secondStage.category_ + ": " + secondStage.message_ + ")";
        return Alert("SIEM-CORRELATION", combinedMsg, secondStage.trigger_, 10);
    }

    friend std::ostream& operator<<(std::ostream& os, const Alert& alert) {
        alert.trigger_.printAlertFormat(os, alert.category_, alert.severity_, alert.message_);
        return os;
    }
};

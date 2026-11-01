#pragma once
#include <ostream>
#include <sstream>

#include "Alert.hpp"
#include "LogEntry.hpp"

class IpTracker {
private:
    LogEntry firstAttempt_;
    int failedAttempts_;
    int totalAttempts_;

public:
    explicit IpTracker(const LogEntry& firstAttempt)
        : firstAttempt_(firstAttempt), failedAttempts_(0), totalAttempts_(0) {
        firstAttempt.updateCounters(totalAttempts_, failedAttempts_);
    }

    bool tracksSameIp(const LogEntry& entry) const {
        return firstAttempt_.hasSameIp(entry);
    }

    void recordAttempt(const LogEntry& entry, int windowSeconds) {
        if (entry.hasWindowExpired(firstAttempt_, windowSeconds)) {
            firstAttempt_ = entry;
            totalAttempts_ = 0;
            failedAttempts_ = 0;
        }
        entry.updateCounters(totalAttempts_, failedAttempts_);
    }

    bool isAttack(int threshold, double minRatio) const {
        if (totalAttempts_ <= 0) {
            return false;
        }
        double currentRatio = (1.0 * failedAttempts_) / totalAttempts_;
        return failedAttempts_ >= threshold && currentRatio >= minRatio;
    }

    Alert createAlert(const LogEntry& lastAttempt) const {
        int duration = lastAttempt.secondsSince(firstAttempt_);
        std::ostringstream msg;
        msg << failedAttempts_ << " SSH failures out of " << totalAttempts_ << " attempts in " << duration << "s";
        return Alert("SSH-BRUTEFORCE", msg.str(), lastAttempt, failedAttempts_);
    }

    friend std::ostream& operator<<(std::ostream& os, const IpTracker& tracker) {
        os << "[SSH Tracker]\n"
           << "      Window start : " << tracker.firstAttempt_ << "\n"
           << "      Failed       : " << tracker.failedAttempts_ << "\n"
           << "      Total        : " << tracker.totalAttempts_;
        return os;
    }
};


#ifndef IP_TRACKER_H
#define IP_TRACKER_H

#include <iostream>
#include <sstream>
#include "Alert.h"
#include "DetectionPolicy.h"
#include "LogEntry.h"

// Numara incercarile SSH ale unui IP intr-o fereastra de timp (pentru brute-force).
class IpTracker {
private:
    LogEntry firstAttempt_;
    int failedAttempts_;
    int totalAttempts_;

public:
    explicit IpTracker(const LogEntry& firstAttempt) : firstAttempt_(firstAttempt), failedAttempts_(0), totalAttempts_(0) {
        firstAttempt.updateCounters(totalAttempts_, failedAttempts_);
    }

    bool tracksSameIp(const LogEntry& entry) const { return firstAttempt_.hasSameIp(entry); }

    // daca a iesit din fereastra, o ia de la capat cu incercarea curenta
    void recordAttempt(const LogEntry& entry, const DetectionPolicy& policy) {
        if (policy.isOutsideWindow(entry.secondsSince(firstAttempt_))) {
            firstAttempt_ = entry;
            totalAttempts_ = 0;
            failedAttempts_ = 0;
        }
        entry.updateCounters(totalAttempts_, failedAttempts_);
    }

    bool isAttack(const DetectionPolicy& policy) const { return policy.isBruteForce(failedAttempts_, totalAttempts_); }

    // merita aratat ca "de urmarit" doar daca a gresit macar o parola
    bool hasFailures() const { return failedAttempts_ > 0; }

    Alert createAlert(const LogEntry& lastAttempt) const {
        std::ostringstream msg;
        msg << failedAttempts_ << " parole gresite din " << totalAttempts_ << " in "
            << lastAttempt.secondsSince(firstAttempt_) << " s";
        return {"brute-force SSH", msg.str(), lastAttempt, failedAttempts_};
    }

    friend std::ostream& operator<<(std::ostream& os, const IpTracker& tracker) {
        os << tracker.firstAttempt_.getIpString() << ": " << tracker.failedAttempts_
           << (tracker.failedAttempts_ == 1 ? " parola gresita" : " parole gresite") << " din " << tracker.totalAttempts_
           << (tracker.totalAttempts_ == 1 ? " incercare" : " incercari");
        return os << " (de la " << tracker.firstAttempt_.getTimestamp() << ")";
    }
};

#endif

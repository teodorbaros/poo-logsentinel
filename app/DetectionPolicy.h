#ifndef DETECTION_POLICY_H
#define DETECTION_POLICY_H

#include <iostream>

// Pragurile de detectie, intr-un singur loc.
// Inainte erau tinute de doua ori (in Analyzer si in SiemConsoleApp) si puteau ajunge diferite.
class DetectionPolicy {
private:
    static constexpr int kDefaultSshThreshold = 5;
    static constexpr int kDefaultPortThreshold = 4;
    static constexpr int kDefaultWindowSeconds = 60;
    static constexpr double kDefaultMinFailureRatio = 0.8;

    int sshThreshold_;        // cate esecuri SSH inseamna brute-force
    int portThreshold_;       // cate porturi distincte inseamna port scan
    int windowSeconds_;       // fereastra de timp in care se numara
    double minFailureRatio_;  // esecuri / incercari, ca sa nu alertam un om care a gresit parola de 2 ori

public:
    DetectionPolicy()
        : sshThreshold_(kDefaultSshThreshold),
          portThreshold_(kDefaultPortThreshold),
          windowSeconds_(kDefaultWindowSeconds),
          minFailureRatio_(kDefaultMinFailureRatio) {}

    DetectionPolicy(int sshThreshold, int portThreshold, int windowSeconds, double minFailureRatio)
        : sshThreshold_(sshThreshold),
          portThreshold_(portThreshold),
          windowSeconds_(windowSeconds),
          minFailureRatio_(minFailureRatio) {}

    bool isValid() const {
        return sshThreshold_ > 0 && portThreshold_ > 0 && windowSeconds_ > 0 && minFailureRatio_ > 0.0 &&
               minFailureRatio_ <= 1.0;
    }

    // Deciziile de detectie - le iau trackerele, in loc sa primeasca 4 numere separate
    bool isBruteForce(int failedAttempts, int totalAttempts) const {
        return totalAttempts > 0 && failedAttempts >= sshThreshold_ &&
               static_cast<double>(failedAttempts) / totalAttempts >= minFailureRatio_;
    }

    bool isPortScan(int distinctPorts) const { return distinctPorts >= portThreshold_; }

    bool isOutsideWindow(int secondsElapsed) const { return secondsElapsed > windowSeconds_; }

    // dupa `policy`: doar ce s-a schimbat, "vechi -> nou"
    void printChangesFrom(std::ostream& os, const DetectionPolicy& old) const {
        bool changed = false;
        if (sshThreshold_ != old.sshThreshold_ || minFailureRatio_ != old.minFailureRatio_) {
            os << "  brute-force SSH: " << old.sshThreshold_ << " -> " << sshThreshold_ << " parole gresite, rata minima "
               << old.minFailureRatio_ << " -> " << minFailureRatio_ << "\n";
            changed = true;
        }
        if (portThreshold_ != old.portThreshold_) {
            os << "  port scan: " << old.portThreshold_ << " -> " << portThreshold_ << " porturi diferite\n";
            changed = true;
        }
        if (windowSeconds_ != old.windowSeconds_) {
            os << "  fereastra de timp: " << old.windowSeconds_ << " -> " << windowSeconds_ << " secunde\n";
            changed = true;
        }
        if (!changed) {
            os << "  (aceleasi valori ca inainte)\n";
        }
    }

    // "brute-force SSH de la 5 parole gresite (rata >= 0.8), port scan de la 4 porturi, in 60 s"
    friend std::ostream& operator<<(std::ostream& os, const DetectionPolicy& policy) {
        return os << "brute-force SSH de la " << policy.sshThreshold_ << " parole gresite (rata >= "
                  << policy.minFailureRatio_ << "), port scan de la " << policy.portThreshold_ << " porturi, in "
                  << policy.windowSeconds_ << " s";
    }
};

#endif

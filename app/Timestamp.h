#ifndef TIMESTAMP_H
#define TIMESTAMP_H

#include <array>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <string>

// Momentul unui eveniment, ca numar de secunde de la 1 ianuarie (log-urile nu au an).
// Inlocuieste codul de timp care era copiat identic in LogEntry si FirewallEntry.
class Timestamp {
private:
    static constexpr int kMonths = 12;
    static constexpr int kSecondsPerMinute = 60;
    static constexpr int kSecondsPerHour = 3600;
    static constexpr int kSecondsPerDay = 86400;
    static constexpr std::array<const char*, kMonths> kMonthNames = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    static constexpr std::array<int, kMonths> kDaysInMonth = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

    int seconds_;   // -1 = data invalida

    // ziua din an (0 = 1 ianuarie) pentru luna `monthIndex` si ziua `day`
    static int dayOfYear(int monthIndex, int day) {
        int days = day - 1;
        for (int m = 0; m < monthIndex; m++) {
            days += kDaysInMonth[static_cast<std::size_t>(m)];
        }
        return days;
    }

public:
    // "Nov", 6, 14, 2, 10  ->  secunde de la inceputul anului; orice camp gresit -> invalid
    Timestamp(const std::string& month, int day, int hour, int minute, int second) : seconds_(-1) {
        const int monthIndex = monthIndexOf(month);
        if (monthIndex < 0 || day < 1 || day > kDaysInMonth[static_cast<std::size_t>(monthIndex)] ||
            hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 59) {
            return;
        }
        seconds_ = dayOfYear(monthIndex, day) * kSecondsPerDay + hour * kSecondsPerHour +
                   minute * kSecondsPerMinute + second;
    }

    // "Nov" -> 10; luna necunoscuta -> -1
    static int monthIndexOf(const std::string& month) {
        for (int i = 0; i < kMonths; i++) {
            if (month == kMonthNames[static_cast<std::size_t>(i)]) {
                return i;
            }
        }
        return -1;
    }

    // 10 -> "Nov" (folosit la conversia log-urilor Windows, care au luna ca numar)
    static std::string monthName(int monthIndex) {
        if (monthIndex < 0 || monthIndex >= kMonths) {
            return "?";
        }
        return kMonthNames[static_cast<std::size_t>(monthIndex)];
    }

    // ora curenta a sistemului, in acelasi format
    static Timestamp now() {
        const std::time_t raw = std::time(nullptr);
        const std::tm* local = std::localtime(&raw);
        if (local == nullptr) {
            return {"?", 0, 0, 0, 0};
        }
        return {monthName(local->tm_mon), local->tm_mday, local->tm_hour, local->tm_min, local->tm_sec};
    }

    bool isValid() const { return seconds_ >= 0; }
    bool isBefore(const Timestamp& other) const { return seconds_ < other.seconds_; }
    int secondsSince(const Timestamp& start) const { return seconds_ - start.seconds_; }

    // Afisare: "Nov 06 14:02:10"
    friend std::ostream& operator<<(std::ostream& os, const Timestamp& ts) {
        if (!ts.isValid()) {
            return os << "?";
        }
        const int dayIndex = ts.seconds_ / kSecondsPerDay;
        const int rest = ts.seconds_ % kSecondsPerDay;
        int month = 0;
        while (month + 1 < kMonths && dayOfYear(month + 1, 1) <= dayIndex) {
            month++;
        }
        const int day = dayIndex - dayOfYear(month, 1) + 1;
        const char oldFill = os.fill('0');
        os << monthName(month) << " " << std::setw(2) << day << " "
           << std::setw(2) << rest / kSecondsPerHour << ":"
           << std::setw(2) << (rest % kSecondsPerHour) / kSecondsPerMinute << ":"
           << std::setw(2) << rest % kSecondsPerMinute;
        os.fill(oldFill);
        return os;
    }
};

#endif

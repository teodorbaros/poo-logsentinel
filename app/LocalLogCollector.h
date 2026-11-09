#ifndef LOCAL_LOG_COLLECTOR_H
#define LOCAL_LOG_COLLECTOR_H

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include "FirewallSource.h"
#include "LogSource.h"
#include "Timestamp.h"

// Citeste log-urile REALE ale sistemului si le transforma in formatul aplicatiei.
// Nu folosim API-uri de sistem (<windows.h> e interzis): sistemul exporta log-ul ca text
// intr-un fisier temporar (std::system), iar noi citim textul linie cu linie.
//
//   Linux SSH : journalctl, procesele sshd          "Nov 06 19:40:01 host sshd[812]: Failed password for root from 1.2.3.4 ..."
//   Linux FW  : journalctl -k (ufw / firewalld)      "Nov 06 19:40:01 host kernel: [UFW BLOCK] ... SRC=1.2.3.4 ... PROTO=TCP ... DPT=22"
//   Win   SSH : PowerShell, Event Log Security       scrie direct formatul aplicatiei
//   Win   FW  : fisierul pfirewall.log               "2026-11-06 19:40:01 DROP TCP 1.2.3.4 10.0.0.2 51122 22 ..."
//
// Securitate: in comenzi intra DOAR `minutes` (un int verificat), niciodata text scris de utilizator.
class LocalLogCollector {
private:
    enum class LineFormat { JournalSsh, KernelFirewall, WindowsFirewall };

    static constexpr int kSecondsPerMinute = 60;

    std::string tempFile_;

    std::string sshExportCommand(int minutes) const {
        const std::string since = std::to_string(minutes);
#if defined(_WIN32)
        // 4625 = logare esuata, 4624 = reusita; doar logari prin retea (tip 3) sau RDP (tip 10)
        return "powershell -NoProfile -Command \""
               "$ci=[Globalization.CultureInfo]::InvariantCulture;"
               "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4625;"
               "StartTime=(Get-Date).AddMinutes(-" + since + ")} -ErrorAction SilentlyContinue | ForEach-Object {"
               "$d=@{}; ([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name]=$_.'#text' };"
               "if (($d['LogonType'] -eq '3' -or $d['LogonType'] -eq '10') -and $d['IpAddress'] -match '^[0-9]+([.][0-9]+){3}$') {"
               "$_.TimeCreated.ToString('MMM dd HH mm ss',$ci) + ' ' + $d['IpAddress'] + ' ' + [int]($_.Id -eq 4625) } }"
               "\" > \"" + tempFile_ + "\"";
#else
        return "journalctl _COMM=sshd _COMM=sshd-session --since \"-" + since + "min\" --no-pager -o short > \"" +
               tempFile_ + "\" 2>/dev/null";
#endif
    }

    std::string firewallExportCommand(int minutes) const {
        return "journalctl -k --since \"-" + std::to_string(minutes) + "min\" --no-pager -o short 2>/dev/null" +
               " | grep \"DPT=\" > \"" + tempFile_ + "\"";
    }

    // textul de dupa "KEY=" pana la primul spatiu:  ("... SRC=1.2.3.4 DST=...", "SRC=") -> "1.2.3.4"
    static std::string fieldValue(const std::string& line, const std::string& key) {
        const std::size_t start = line.find(key);
        if (start == std::string::npos) {
            return "";
        }
        const std::size_t valueStart = start + key.size();
        return line.substr(valueStart, line.find(' ', valueStart) - valueStart);
    }

    // "Nov 06 19:40:01 ..." -> "Nov 06 19 40 01"
    static std::string syslogTime(const std::string& line) {
        std::istringstream fields(line);
        std::string month;
        std::string day;
        std::string clock;
        if (!(fields >> month >> day >> clock)) {
            return "";
        }
        for (char& c : clock) {
            if (c == ':') {
                c = ' ';
            }
        }
        return month + " " + day + " " + clock;
    }

    // Linux SSH. Numaram doar "Failed password" si "Accepted": la un user inexistent sshd scrie si
    // "Invalid user ..." pentru ACEEASI incercare, deci l-am numara de doua ori.
    static std::string convertJournalSsh(const std::string& line) {
        const bool failed = line.find("Failed password") != std::string::npos;
        const bool accepted = line.find("Accepted ") != std::string::npos;
        const std::size_t from = line.find(" from ");
        if ((!failed && !accepted) || from == std::string::npos) {
            return "";
        }
        std::istringstream rest(line.substr(from + std::string(" from ").size()));
        std::string ip;
        rest >> ip;
        return syslogTime(line) + " " + ip + (failed ? " 1" : " 0");
    }

    static std::string convertKernelFirewall(const std::string& line) {
        const std::string ip = fieldValue(line, "SRC=");
        const std::string port = fieldValue(line, "DPT=");
        const std::string protocol = fieldValue(line, "PROTO=");
        if (ip.empty() || port.empty() || protocol.empty()) {
            return "";
        }
        const bool blocked = line.find("BLOCK") != std::string::npos || line.find("DROP") != std::string::npos ||
                             line.find("REJECT") != std::string::npos;
        return syslogTime(line) + " " + ip + " " + port + " " + protocol + (blocked ? " 1" : " 0");
    }

    // Windows pfirewall.log; pastram doar liniile din ultimele `minutes` minute
    static std::string convertWindowsFirewall(const std::string& line, int minutes) {
        std::istringstream fields(line);
        int year = 0;
        int month = 0;
        int day = 0;
        int hour = 0;
        int minute = 0;
        int second = 0;
        char sep = ' ';
        std::string action;
        std::string protocol;
        std::string srcIp;
        std::string dstIp;
        std::string srcPort;
        std::string dstPort;
        // "2026-11-06 19:40:01 DROP TCP ..."  ->  numerele, cu separatorii '-' si ':' sariti prin `sep`
        if (line.empty() || line[0] == '#' ||
            !(fields >> year >> sep >> month >> sep >> day >> hour >> sep >> minute >> sep >> second >> action >>
              protocol >> srcIp >> dstIp >> srcPort >> dstPort) ||
            dstPort == "-") {
            return "";
        }
        const std::string monthName = Timestamp::monthName(month - 1);
        const Timestamp when(monthName, day, hour, minute, second);
        const int age = Timestamp::now().secondsSince(when);
        if (!when.isValid() || age < 0 || age > minutes * kSecondsPerMinute) {
            return "";
        }
        const bool blocked = action == "DROP" || action == "BLOCK";
        return monthName + " " + std::to_string(day) + " " + std::to_string(hour) + " " + std::to_string(minute) +
               " " + std::to_string(second) + " " + srcIp + " " + dstPort + " " + protocol + (blocked ? " 1" : " 0");
    }

    // O singura functie pentru toate formatele: citeste, converteste, pastreaza liniile recunoscute
    static std::string convertAll(std::istream& in, LineFormat format, int minutes) {
        std::string result;
        std::string line;
        while (std::getline(in, line)) {
            std::string converted;
            if (format == LineFormat::JournalSsh) {
                converted = convertJournalSsh(line);
            } else if (format == LineFormat::KernelFirewall) {
                converted = convertKernelFirewall(line);
            } else {
                converted = convertWindowsFirewall(line, minutes);
            }
            if (!converted.empty()) {
                result += converted + "\n";
            }
        }
        return result;
    }

    // ruleaza comanda de export si intoarce continutul fisierului temporar (apoi il sterge)
    std::string runExport(const std::string& command, std::ostream& out) const {
        out << "Citesc log-urile sistemului...\n";
        if (std::system(command.c_str()) == -1) {
            out << "Eroare: nu am putut porni comanda care exporta log-urile.\n";
            return "";
        }
        std::ifstream exported(tempFile_);
        std::stringstream content;
        content << exported.rdbuf();
        exported.close();
        std::remove(tempFile_.c_str());
        return content.str();
    }

public:
    explicit LocalLogCollector(const std::string& tempFile) : tempFile_(tempFile) {}

    static bool isSupportedPlatform() {
#if defined(_WIN32) || defined(__linux__)
        return true;
#else
        return false;
#endif
    }

    // intoarce cate evenimente SSH au fost adaugate in `target`
    int collectSsh(int minutes, LogSource& target, std::ostream& out) const {
        std::istringstream exported(runExport(sshExportCommand(minutes), out));
#if defined(_WIN32)
        std::istringstream converted(exported.str());   // PowerShell a scris deja formatul aplicatiei
#else
        std::istringstream converted(convertAll(exported, LineFormat::JournalSsh, minutes));
#endif
        const int added = target.ingestUntilEof(converted);
        if (added == 0) {
#if defined(_WIN32)
            out << "Nu am gasit nicio logare prin retea in ultimele " << minutes << " minute.\n"
                << "Daca te asteptai la evenimente: porneste terminalul ca Administrator si verifica auditarea\n"
                << "cu 'auditpol /get /subcategory:Logon'.\n";
#else
            out << "Nu am gasit nicio incercare de logare SSH in ultimele " << minutes << " minute.\n"
                << "Daca te asteptai la evenimente: ruleaza aplicatia cu sudo sau adauga-te in grup cu\n"
                << "'sudo usermod -aG systemd-journal $USER' (apoi deschide alt terminal).\n";
#endif
        }
        return added;
    }

    int collectFirewall(int minutes, FirewallSource& target, std::ostream& out) const {
#if defined(_WIN32)
        // logarea e OPRITA implicit: Windows Defender Firewall -> Advanced settings -> Properties -> Logging
        std::ifstream log("C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log");
        if (!log.is_open()) {
            out << "Eroare: nu pot deschide pfirewall.log. Porneste terminalul ca Administrator si activeaza\n"
                << "logarea din Windows Defender Firewall -> Advanced settings -> Properties -> Logging.\n";
            return 0;
        }
        std::istringstream converted(convertAll(log, LineFormat::WindowsFirewall, minutes));
#else
        std::istringstream exported(runExport(firewallExportCommand(minutes), out));
        std::istringstream converted(convertAll(exported, LineFormat::KernelFirewall, minutes));
#endif
        const int added = target.ingestUntilEof(converted);
        if (added == 0) {
            out << "Nu am gasit niciun pachet de firewall in ultimele " << minutes << " minute.\n"
                << "Firewall-ul logheaza doar daca e pornit: 'sudo ufw logging on' sau, pe firewalld,\n"
                << "'sudo firewall-cmd --set-log-denied=all'.\n";
        }
        return added;
    }

    friend std::ostream& operator<<(std::ostream& os, const LocalLogCollector& collector) {
#if defined(_WIN32)
        os << "Surse locale: Event Log Security (logari) si pfirewall.log";
#elif defined(__linux__)
        os << "Surse locale: journalctl (sshd) si log-ul kernel-ului (ufw / firewalld)";
#else
        os << "Scanarea locala nu e disponibila pe acest sistem";
#endif
        return os << " (fisier temporar: " << collector.tempFile_ << ")";
    }
};

#endif

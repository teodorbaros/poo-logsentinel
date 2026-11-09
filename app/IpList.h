#ifndef IP_LIST_H
#define IP_LIST_H

#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include "FirewallBlockAdvisor.h"
#include "IpRange.h"
#include "Ipv4Address.h"

// Whitelist sau blacklist: IP-uri/subnet-uri cu motivul pentru care sunt in lista.
// Lista se citeste dintr-un fisier text la pornire si se salveaza la fiecare modificare:
//     192.168.1.20 laptopul meu
//     10.0.0.0/8 reteaua interna
class IpList {
private:
    static constexpr int kRangeColumn = 20;   // "255.255.255.255/32" + spatiu

    std::string name_;
    std::string filePath_;
    std::vector<IpRange> ranges_;
    std::vector<std::string> reasons_;   // reasons_[i] = motivul pentru ranges_[i]

    void save(std::ostream& out) const {
        std::ofstream file(filePath_);
        if (!file.is_open()) {
            out << "Eroare: nu pot salva " << name_ << " in " << filePath_ << " (permisiuni?). Modificarea se pierde la iesire.\n";
            return;
        }
        for (std::size_t i = 0; i < ranges_.size(); i++) {
            file << ranges_[i] << " " << reasons_[i] << "\n";
        }
    }

public:
    IpList(const std::string& name, const std::string& filePath) : name_(name), filePath_(filePath) {}

    // false (cu mesaj) daca intrarea e invalida sau exista deja
    bool add(const std::string& entry, const std::string& reason, std::ostream& out) {
        const IpRange range(entry);
        if (!range.isValid()) {
            out << "Eroare: '" << entry << "' nu e o adresa IP sau un subnet valid. Exemple: 10.0.0.5, 10.0.0.0/24\n";
            return false;
        }
        if (containsRange(range)) {
            out << range << " e deja in " << name_ << ".\n";
            return false;
        }
        ranges_.push_back(range);
        reasons_.push_back(reason.empty() ? "adaugat manual" : reason);
        out << range << " a fost adaugat in " << name_ << " (" << reasons_.back() << ").\n";
        save(out);
        return true;
    }

    bool remove(const std::string& entry, std::ostream& out) {
        const IpRange target(entry);
        for (std::size_t i = 0; i < ranges_.size(); i++) {
            if (ranges_[i].sameAs(target)) {
                out << ranges_[i] << " a fost scos din " << name_ << ".\n";
                ranges_.erase(ranges_.begin() + static_cast<std::ptrdiff_t>(i));
                reasons_.erase(reasons_.begin() + static_cast<std::ptrdiff_t>(i));
                save(out);
                return true;
            }
        }
        out << entry << " nu e in " << name_ << ". Vezi lista cu '" << name_ << " list'.\n";
        return false;
    }

    // Citeste fisierul (daca exista); liniile goale si cele care incep cu '#' sunt ignorate.
    // Intoarce cate intrari are lista; anunta doar liniile invalide.
    int load(std::ostream& out) {
        std::ifstream file(filePath_);
        if (!file.is_open()) {
            return 0;
        }
        std::string line;
        int invalidCount = 0;
        while (std::getline(file, line)) {
            std::istringstream fields(line);
            std::string entry;
            if (!(fields >> entry) || entry[0] == '#') {
                continue;
            }
            std::string reason;
            std::getline(fields >> std::ws, reason);
            const IpRange range(entry);
            if (!range.isValid()) {
                invalidCount++;
            } else if (!containsRange(range)) {
                ranges_.push_back(range);
                reasons_.push_back(reason);
            }
        }
        if (invalidCount > 0) {
            out << "Atentie: " << invalidCount << " linii din " << filePath_ << " nu sunt IP-uri valide si au fost sarite.\n";
        }
        return static_cast<int>(ranges_.size());
    }

    int size() const { return static_cast<int>(ranges_.size()); }

    // IP-ul e acoperit de vreo intrare (IP exact sau subnet)?
    bool contains(const Ipv4Address& ip) const {
        for (const IpRange& range : ranges_) {
            if (range.contains(ip)) {
                return true;
            }
        }
        return false;
    }

    // exista deja exact intrarea asta?
    bool containsRange(const IpRange& candidate) const {
        for (const IpRange& range : ranges_) {
            if (range.sameAs(candidate)) {
                return true;
            }
        }
        return false;
    }

    // vreo intrare se suprapune cu range-ul? (ca sa nu blocam ceva ce e in whitelist)
    bool overlaps(const IpRange& candidate) const {
        for (const IpRange& range : ranges_) {
            if (range.overlaps(candidate)) {
                return true;
            }
        }
        return false;
    }

    // intrarile cu un anumit prefix (32 = IP-uri individuale, 24 = subnet-uri /24)
    std::vector<IpRange> rangesWithPrefix(int prefix) const {
        std::vector<IpRange> result;
        for (const IpRange& range : ranges_) {
            if (range.getPrefix() == prefix) {
                result.push_back(range);
            }
        }
        return result;
    }

    // Scrie un script cu cate o comanda de blocare pe linie, ca utilizatorul sa-l citeasca inainte sa-l ruleze
    bool exportBlockScript(const std::string& path, std::ostream& out) const {
        if (ranges_.empty()) {
            out << name_ << " e goala, nu am ce exporta.\n";
            return false;
        }
        std::ofstream script(path);
        if (!script.is_open()) {
            out << "Eroare: nu pot crea fisierul " << path << ".\n";
            return false;
        }
        script << "# Generat de LogSentinel SIEM - verifica fiecare linie inainte sa rulezi!\n";
        for (std::size_t i = 0; i < ranges_.size(); i++) {
            script << "# Motiv: " << reasons_[i] << "\n" << FirewallBlockAdvisor(ranges_[i]).blockCommand() << "\n";
        }
        out << "Am scris " << ranges_.size() << " comenzi de blocare in " << path << ".\n"
            << "Citeste fisierul inainte sa-l rulezi (de exemplu: sudo sh " << path << ").\n";
        return true;
    }

    friend std::ostream& operator<<(std::ostream& os, const IpList& list) {
        if (list.ranges_.empty()) {
            return os << list.name_ << ": goala";
        }
        os << list.name_ << " (" << list.ranges_.size() << "):";
        for (std::size_t i = 0; i < list.ranges_.size(); i++) {
            os << "\n  " << std::left << std::setw(kRangeColumn) << list.ranges_[i].toText() << std::right
               << list.reasons_[i];
        }
        return os;
    }
};

#endif

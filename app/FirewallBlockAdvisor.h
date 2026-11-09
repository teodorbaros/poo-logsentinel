#ifndef FIREWALL_BLOCK_ADVISOR_H
#define FIREWALL_BLOCK_ADVISOR_H

#include <cstdint>
#include <iostream>
#include <string>
#include "IpRange.h"

// Comenzile de firewall care blocheaza un IP/subnet pe sistemul curent.
// Aplicatia NU le ruleaza: le afiseaza sau le scrie intr-un script, iar utilizatorul le verifica si le ruleaza.
// Comenzile sunt scrise o singura data aici si refolosite (afisare + export script).
class FirewallBlockAdvisor {
private:
    IpRange target_;

    std::string ruleName() const { return "LogSentinel block " + target_.toText(); }

public:
    explicit FirewallBlockAdvisor(const IpRange& target) : target_(target) {}

    std::string blockCommand() const {
#if defined(_WIN32)
        return "netsh advfirewall firewall add rule name=\"" + ruleName() + "\" dir=in action=block remoteip=" +
               target_.toText();
#else
        // "insert 1": ufw aplica PRIMA regula care se potriveste, deci un "allow 22" mai vechi ar castiga
        return "sudo ufw insert 1 deny from " + target_.toText() + " to any";
#endif
    }

    std::string unblockCommand() const {
#if defined(_WIN32)
        return "netsh advfirewall firewall delete rule name=\"" + ruleName() + "\"";
#else
        return "sudo ufw delete deny from " + target_.toText() + " to any";
#endif
    }

    std::string verifyCommand() const {
#if defined(_WIN32)
        return "netsh advfirewall firewall show rule name=\"" + ruleName() + "\"";
#else
        return "sudo ufw status numbered";
#endif
    }

    friend std::ostream& operator<<(std::ostream& os, const FirewallBlockAdvisor& advisor) {
        if (!advisor.target_.isValid()) {
            return os << "Eroare: aceasta nu e o adresa IP sau un subnet valid.\n";
        }
        const std::uint64_t count = advisor.target_.addressCount();
        os << "Ca sa blochezi " << advisor.target_ << " (" << count << (count == 1 ? " adresa" : " adrese")
#if defined(_WIN32)
           << ") in Windows Firewall, ruleaza ca Administrator:\n"
#else
           << ") cu ufw:\n"
#endif
           << "  blocare:    " << advisor.blockCommand() << "\n"
           << "  anulare:    " << advisor.unblockCommand() << "\n"
           << "  verificare: " << advisor.verifyCommand() << "\n";
#if !defined(_WIN32)
        os << "Daca ufw nu are inca nicio regula, scrie 'sudo ufw deny from ...' (fara 'insert 1').\n";
#endif
        return os;
    }
};

#endif

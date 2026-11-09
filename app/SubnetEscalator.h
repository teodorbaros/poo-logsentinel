#ifndef SUBNET_ESCALATOR_H
#define SUBNET_ESCALATOR_H

#include <iostream>
#include <map>
#include <string>
#include <vector>
#include "IpList.h"
#include "IpRange.h"

// Propunerea de a bloca un subnet intreg, cu dovezile care o sustin.
class SubnetProposal {
private:
    IpRange range_;
    int evidence_;
    std::string evidenceUnit_;

public:
    SubnetProposal(const IpRange& range, int evidence, const std::string& evidenceUnit)
        : range_(range), evidence_(evidence), evidenceUnit_(evidenceUnit) {}

    const IpRange& getRange() const { return range_; }

    // "256 adrese, 3 IP-uri in blacklist" - motivul trecut in blacklist
    std::string evidenceText() const {
        return std::to_string(range_.addressCount()) + " adrese, " + std::to_string(evidence_) + " " + evidenceUnit_ +
               " in blacklist";
    }

    // "45.12.3.0/24 = 256 adrese, 3 IP-uri rele gasite"
    friend std::ostream& operator<<(std::ostream& os, const SubnetProposal& proposal) {
        return os << proposal.range_ << " (" << proposal.evidenceText() << ")";
    }
};

// Escaladare pe baza de dovezi:
//   /24 daca are cel putin minBadIps IP-uri din blacklist
//   /16 daca are cel putin minBadSubnets subnet-uri /24 rele
// Niciodata mai larg de /16, niciodata ceva ce atinge whitelist-ul sau o retea privata.
class SubnetEscalator {
private:
    static constexpr int kSingleIp = 32;
    static constexpr int kSmallPrefix = 24;
    static constexpr int kLargePrefix = 16;

    int minBadIpsPer24_;
    int minBad24sPer16_;

    // Cate elemente din `items` cad in fiecare subnet /prefix.  Cheia = subnetul ca text.
    static std::map<std::string, int> countBySubnet(const std::vector<IpRange>& items, int prefix) {
        std::map<std::string, int> counts;
        for (const IpRange& item : items) {
            counts[IpRange::containing(item.networkAddress(), prefix).toText()]++;
        }
        return counts;
    }

    static bool isSafeToPropose(const IpRange& range, const IpList& blacklist, const IpList& whitelist) {
        return range.isValid() && !whitelist.overlaps(range) && !range.networkAddress().isPrivate() &&
               !blacklist.containsRange(range);
    }

public:
    SubnetEscalator(int minBadIpsPer24, int minBad24sPer16)
        : minBadIpsPer24_(minBadIpsPer24), minBad24sPer16_(minBad24sPer16) {}

    std::vector<SubnetProposal> propose(const IpList& blacklist, const IpList& whitelist) const {
        // Pasul 1: /24 cu destule IP-uri rele
        std::vector<IpRange> bad24s = blacklist.rangesWithPrefix(kSmallPrefix);   // cele deja blocate conteaza si ele
        std::vector<SubnetProposal> proposals24;
        for (const auto& entry : countBySubnet(blacklist.rangesWithPrefix(kSingleIp), kSmallPrefix)) {
            const IpRange subnet(entry.first);   // entry.first = subnetul, entry.second = cate IP-uri rele are
            const int count = entry.second;
            if (count < minBadIpsPer24_) {
                continue;
            }
            if (!blacklist.containsRange(subnet)) {
                bad24s.push_back(subnet);
            }
            if (isSafeToPropose(subnet, blacklist, whitelist)) {
                proposals24.emplace_back(subnet, count, "IP-uri");
            }
        }

        // Pasul 2: /16 cu destule /24 rele; un /16 propus le acopera pe /24-urile din el
        std::vector<SubnetProposal> result;
        for (const auto& entry : countBySubnet(bad24s, kLargePrefix)) {
            const IpRange subnet(entry.first);
            const int count = entry.second;
            if (count >= minBad24sPer16_ && isSafeToPropose(subnet, blacklist, whitelist)) {
                result.emplace_back(subnet, count, "subnet-uri /24");
            }
        }
        for (const SubnetProposal& small : proposals24) {
            bool covered = false;
            for (const SubnetProposal& large : result) {
                covered = covered || large.getRange().overlaps(small.getRange());
            }
            if (!covered) {
                result.push_back(small);
            }
        }
        return result;
    }

    friend std::ostream& operator<<(std::ostream& os, const SubnetEscalator& escalator) {
        return os << "Propun un /24 cand are cel putin " << escalator.minBadIpsPer24_
                  << " IP-uri in blacklist si un /16 cand are cel putin " << escalator.minBad24sPer16_
                  << " subnet-uri /24 in blacklist.";
    }
};

#endif

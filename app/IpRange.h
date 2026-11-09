#ifndef IP_RANGE_H
#define IP_RANGE_H

#include <cstdint>
#include <iostream>
#include <string>
#include "Ipv4Address.h"

// Un IP ("10.0.0.5") sau un subnet ("192.168.1.0/24").
// Un IP e in subnet daca (ip & masca) == adresa retelei.
class IpRange {
private:
    static constexpr int kMaxPrefix = 32;

    std::string text_;
    std::uint32_t network_;
    std::uint32_t mask_;
    int prefix_;
    bool valid_;

    // /24 -> 255.255.255.0 ; /0 tratat separat (shift cu 32 de biti e comportament nedefinit)
    static std::uint32_t maskFor(int prefix) {
        return prefix == 0 ? 0U : (0xFFFFFFFFU << (kMaxPrefix - prefix));
    }

    // "24" -> 24 ; orice altceva decat 1-2 cifre intre 0 si 32 -> -1
    static int parsePrefix(const std::string& text) {
        if (text.empty() || text.size() > 2) {
            return -1;
        }
        int value = 0;
        for (const char c : text) {
            if (c < '0' || c > '9') {
                return -1;
            }
            value = value * 10 + (c - '0');
        }
        return value <= kMaxPrefix ? value : -1;
    }

public:
    explicit IpRange(const std::string& text) : text_(text), network_(0), mask_(0), prefix_(kMaxPrefix), valid_(false) {
        const std::size_t slash = text.find('/');
        const Ipv4Address address(text.substr(0, slash));
        if (slash != std::string::npos) {
            prefix_ = parsePrefix(text.substr(slash + 1));
        }
        if (!address.isValid() || prefix_ < 0) {
            return;
        }
        mask_ = maskFor(prefix_);
        network_ = address.toNumber() & mask_;
        // forma normalizata: "192.168.1.77/24" devine "192.168.1.0/24", iar "/32" dispare
        text_ = Ipv4Address::numberToText(network_);
        if (prefix_ < kMaxPrefix) {
            text_ += "/" + std::to_string(prefix_);
        }
        valid_ = true;
    }

    // subnetul /prefix care contine adresa: (45.12.3.9, 24) -> 45.12.3.0/24
    static IpRange containing(const Ipv4Address& ip, int prefix) {
        return IpRange(ip.toString() + "/" + std::to_string(prefix));
    }

    bool isValid() const { return valid_; }
    const std::string& toText() const { return text_; }
    int getPrefix() const { return prefix_; }

    bool contains(const Ipv4Address& ip) const { return valid_ && ip.isValid() && (ip.toNumber() & mask_) == network_; }

    bool sameAs(const IpRange& other) const {
        return valid_ && other.valid_ && network_ == other.network_ && prefix_ == other.prefix_;
    }

    // se suprapun daca, sub masca celui mai mare dintre ele, au aceeasi retea
    bool overlaps(const IpRange& other) const {
        const std::uint32_t common = mask_ & other.mask_;
        return valid_ && other.valid_ && (network_ & common) == (other.network_ & common);
    }

    // 2^(32 - prefix); uint64 pentru ca /0 are 2^32 adrese
    std::uint64_t addressCount() const { return std::uint64_t{1} << (kMaxPrefix - prefix_); }

    Ipv4Address networkAddress() const { return Ipv4Address(Ipv4Address::numberToText(network_)); }

    friend std::ostream& operator<<(std::ostream& os, const IpRange& range) { return os << range.text_; }
};

#endif

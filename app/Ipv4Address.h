#ifndef IPV4_ADDRESS_H
#define IPV4_ADDRESS_H

#include <cstdint>
#include <iostream>
#include <string>

// O adresa IPv4 validata, tinuta si ca text si ca numar pe 32 de biti.
// Inlocuieste validarea care era copiata identic in LogEntry si FirewallEntry.
class Ipv4Address {
private:
    static constexpr std::uint32_t kMaxOctet = 255;

    std::string text_;
    std::uint32_t value_;
    bool valid_;

    // "192.168.1.50" -> 4 octeti intre 0 si 255, separati de exact 3 puncte
    void parse() {
        std::uint32_t octet = 0;
        int digits = 0;
        int dots = 0;
        for (const char c : text_) {
            if (c == '.') {
                if (digits == 0) {
                    return;
                }
                value_ = (value_ << 8) | octet;
                dots++;
                octet = 0;
                digits = 0;
            } else if (c >= '0' && c <= '9') {
                octet = octet * 10 + static_cast<std::uint32_t>(c - '0');
                digits++;
                if (digits > 3 || octet > kMaxOctet) {
                    return;
                }
            } else {
                return;
            }
        }
        if (dots == 3 && digits > 0) {
            value_ = (value_ << 8) | octet;
            valid_ = true;
        }
    }

public:
    explicit Ipv4Address(const std::string& text) : text_(text), value_(0), valid_(false) { parse(); }

    bool isValid() const { return valid_; }
    std::uint32_t toNumber() const { return value_; }
    const std::string& toString() const { return text_; }

    bool sameAs(const Ipv4Address& other) const { return valid_ && other.valid_ && value_ == other.value_; }

    // retele locale: 10/8, 172.16/12, 192.168/16 si 127/8 (loopback)
    bool isPrivate() const {
        if (!valid_) {
            return false;
        }
        const std::uint32_t first = value_ >> 24;
        const std::uint32_t second = (value_ >> 16) & kMaxOctet;
        return first == 10 || first == 127 || (first == 172 && second >= 16 && second <= 31) ||
               (first == 192 && second == 168);
    }

    // 0x2D0C0300 -> "45.12.3.0"
    static std::string numberToText(std::uint32_t number) {
        return std::to_string((number >> 24) & kMaxOctet) + "." + std::to_string((number >> 16) & kMaxOctet) + "." +
               std::to_string((number >> 8) & kMaxOctet) + "." + std::to_string(number & kMaxOctet);
    }

    friend std::ostream& operator<<(std::ostream& os, const Ipv4Address& ip) { return os << ip.text_; }
};

#endif

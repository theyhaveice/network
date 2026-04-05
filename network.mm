#include "network.h"
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if_dl.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <thread>
#include <mutex>
#include <atomic>
#import <Foundation/Foundation.h>
#include <dns_sd.h>

static std::map<std::string, std::string> g_oui_cache;
static std::mutex g_oui_mtx;

static std::string parse_dns_name(const void* rdata, uint16_t rdlen) {
    const uint8_t* p   = static_cast<const uint8_t*>(rdata);
    const uint8_t* end = p + rdlen;
    std::string result;
    while (p < end && *p != 0) {
        uint8_t len = *p++;
        if (p + len > end) break;
        if (!result.empty()) result += '.';
        result.append(reinterpret_cast<const char*>(p), len);
        p += len;
    }
    return result;
}

struct MDNSContext { std::string hostname; bool done = false; };

static void DNSSD_API mdns_reply_cb(
    DNSServiceRef, DNSServiceFlags, uint32_t,
    DNSServiceErrorType errorCode, const char*,
    uint16_t rrtype, uint16_t,
    uint16_t rdlen, const void* rdata,
    uint32_t, void* context)
{
    if (errorCode != kDNSServiceErr_NoError || rrtype != kDNSServiceType_PTR) return;
    MDNSContext* ctx = static_cast<MDNSContext*>(context);
    std::string name = parse_dns_name(rdata, rdlen);
    if (!name.empty()) { ctx->hostname = name; ctx->done = true; }
}

std::string mdns_reverse_lookup(const std::string& ipv4) {
    unsigned int a, b, c, d;
    if (sscanf(ipv4.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return "n/a";
    char arpa[64];
    snprintf(arpa, sizeof(arpa), "%u.%u.%u.%u.in-addr.arpa.", d, c, b, a);
    MDNSContext ctx;
    DNSServiceRef sdRef = nullptr;
    DNSServiceErrorType err = DNSServiceQueryRecord(
        &sdRef, kDNSServiceFlagsForceMulticast, kDNSServiceInterfaceIndexAny,
        arpa, kDNSServiceType_PTR, kDNSServiceClass_IN, mdns_reply_cb, &ctx);
    if (err != kDNSServiceErr_NoError || !sdRef) return "n/a";
    int fd = DNSServiceRefSockFD(sdRef);
    struct timeval tv = { 2, 0 };
    fd_set fds; FD_ZERO(&fds); FD_SET(fd, &fds);
    if (select(fd + 1, &fds, nullptr, nullptr, &tv) > 0)
        DNSServiceProcessResult(sdRef);
    DNSServiceRefDeallocate(sdRef);
    return ctx.done ? ctx.hostname : "n/a";
}

std::string get_hostname_from_arp(const std::string& ip) {
    std::string cmd = "arp -a | grep \"(" + ip + ")\"";
    std::shared_ptr<FILE> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) return "n/a";
    char buffer[256];
    if (fgets(buffer, sizeof(buffer), pipe.get())) {
        std::string line(buffer);
        size_t sp = line.find(' ');
        if (sp != std::string::npos) {
            std::string name = line.substr(0, sp);
            if (name != "?" && name != ip && name.find('.') != std::string::npos)
                return name;
        }
    }
    return "n/a";
}

ARPInfo get_arp_info(const std::string& ip) {
    ARPInfo info;
    std::string cmd = "arp -n " + ip + " 2>/dev/null";
    std::shared_ptr<FILE> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) return info;
    char buf[512];
    while (fgets(buf, sizeof(buf), pipe.get())) {
        std::string line(buf);
        if (line.find(ip) == std::string::npos) continue;
        if (line.find("(incomplete)") != std::string::npos) return info;
        std::istringstream iss(line);
        std::string tok;
        std::vector<std::string> tokens;
        while (iss >> tok) tokens.push_back(tok);
        for (size_t i = 0; i < tokens.size(); ++i) {
            const std::string& t = tokens[i];
            int colons = 0;
            for (char c : t) if (c == ':') colons++;
            if (colons == 5) info.mac = t;
            if (t == "expires" && i + 2 < tokens.size())
                info.ttl = tokens[i + 1] + " " + tokens[i + 2];
        }
    }
    return info;
}

std::string normalise_mac(std::string mac) {
    for (char& c : mac) c = (char)toupper((unsigned char)c);
    return mac;
}

std::string lookup_vendor(const std::string& mac) {
    if (mac == "n/a" || mac.size() < 8) return "n/a";
    std::string oui = mac.substr(0, 8);
    for (char& c : oui) c = (char)toupper((unsigned char)c);

    {
        std::lock_guard<std::mutex> lk(g_oui_mtx);
        auto it = g_oui_cache.find(oui);
        if (it != g_oui_cache.end()) return it->second;
    }

    std::string vendor = "n/a";
    const char* paths[] = {
        "/usr/share/arp-scan/ieee-oui.txt",
        "/usr/local/share/arp-scan/ieee-oui.txt",
        "/opt/homebrew/share/arp-scan/ieee-oui.txt",
        nullptr
    };
    for (int i = 0; paths[i]; ++i) {
        std::ifstream f(paths[i]);
        if (!f.is_open()) continue;
        std::string line;
        std::string needle = oui;
        needle.erase(std::remove(needle.begin(), needle.end(), ':'), needle.end());
        while (std::getline(f, line)) {
            if (line.size() < 7) continue;
            std::string prefix = line.substr(0, 6);
            for (char& c : prefix) c = (char)toupper((unsigned char)c);
            if (prefix == needle) {
                vendor = line.substr(7);
                while (!vendor.empty() && (vendor.back() == '\n' || vendor.back() == '\r'))
                    vendor.pop_back();
                break;
            }
        }
        if (vendor != "n/a") break;
    }

    if (vendor == "n/a") {
        std::string stripped = oui;
        stripped.erase(std::remove(stripped.begin(), stripped.end(), ':'), stripped.end());
        std::string cmd = "curl -sf --max-time 2 \"https://api.macvendors.com/" + stripped + "\"";
        std::shared_ptr<FILE> pipe(popen(cmd.c_str(), "r"), pclose);
        if (pipe) {
            char buf[256] = {};
            if (fgets(buf, sizeof(buf), pipe.get())) {
                std::string resp(buf);
                while (!resp.empty() && (resp.back() == '\n' || resp.back() == '\r'))
                    resp.pop_back();
                if (!resp.empty() && resp.find("errors") == std::string::npos)
                    vendor = resp;
            }
        }
    }

    {
        std::lock_guard<std::mutex> lk(g_oui_mtx);
        g_oui_cache[oui] = vendor;
    }
    return vendor;
}

std::string get_ipv6(const std::string& hostname) {
    if (hostname == "n/a") return "n/a";
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(hostname.c_str(), nullptr, &hints, &res) == 0 && res) {
        char buf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6,
                  &reinterpret_cast<struct sockaddr_in6*>(res->ai_addr)->sin6_addr,
                  buf, sizeof(buf));
        freeaddrinfo(res);
        return buf;
    }
    if (res) freeaddrinfo(res);
    return "n/a";
}

bool is_host_reachable(const std::string& ip) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(7);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
    sendto(sock, "probe", 5, 0, (struct sockaddr*)&addr, sizeof(addr));
    close(sock);
    usleep(150000);
    std::string cmd = "arp -n " + ip + " 2>/dev/null";
    std::shared_ptr<FILE> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) return false;
    char buf[256];
    while (fgets(buf, sizeof(buf), pipe.get())) {
        std::string line(buf);
        if (line.find("(incomplete)") != std::string::npos) return false;
        if (line.find(ip) != std::string::npos && line.find(':') != std::string::npos)
            return true;
    }
    return false;
}

NetworkDevice get_device_info(const std::string& target_ip, bool check_online) {
    NetworkDevice dev;
    dev.ipv4 = target_ip;

    if (check_online) {
        dev.online = is_host_reachable(target_ip);
        if (!dev.online) return dev;
    } else {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock >= 0) {
            struct sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port   = htons(7);
            inet_pton(AF_INET, target_ip.c_str(), &addr.sin_addr);
            sendto(sock, "probe", 5, 0, (struct sockaddr*)&addr, sizeof(addr));
            close(sock);
            usleep(150000);
        }
        dev.online = true;
    }

    ARPInfo arp = get_arp_info(target_ip);
    dev.mac    = arp.mac.empty()  ? "n/a" : normalise_mac(arp.mac);
    dev.ttl    = arp.ttl.empty()  ? "n/a" : arp.ttl;
    dev.vendor = lookup_vendor(dev.mac);

    dev.hostname = mdns_reverse_lookup(target_ip);
    if (dev.hostname == "n/a") dev.hostname = get_hostname_from_arp(target_ip);

    if (dev.hostname == "n/a") {
        @autoreleasepool {
            NSString* ns = [NSString stringWithUTF8String:target_ip.c_str()];
            NSHost* host = [NSHost hostWithAddress:ns];
            if (host && [[host names] count] > 0) {
                std::string found = [[[host names] objectAtIndex:0] UTF8String];
                if (found != target_ip) dev.hostname = found;
            }
        }
    }

    if (dev.hostname == "n/a") {
        struct sockaddr_in sa{};
        sa.sin_family = AF_INET;
        inet_pton(AF_INET, target_ip.c_str(), &sa.sin_addr);
        char hbuf[NI_MAXHOST];
        if (getnameinfo(reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa),
                        hbuf, sizeof(hbuf), nullptr, 0, NI_NAMEREQD) == 0)
            dev.hostname = hbuf;
    }

    dev.ipv6       = get_ipv6(dev.hostname);
    dev.has_detail = (dev.hostname != "n/a" || dev.ipv6 != "n/a" ||
                      dev.mac != "n/a"      || dev.vendor != "n/a");
    return dev;
}

NetworkDevice get_current_device() {
    NetworkDevice dev;
    dev.online     = true;
    dev.has_detail = true;

    @autoreleasepool {
        NSHost* host = [NSHost currentHost];
        if (host) {
            dev.hostname = [[host name] UTF8String];
            NSArray* addrs = [host addresses];
            for (NSString* addr in addrs) {
                std::string a = [addr UTF8String];
                if (a.find(':') != std::string::npos && dev.ipv6 == "n/a") {
                    if (a.substr(0, 2) != "fe" && a.substr(0, 2) != "FE")
                        dev.ipv6 = a;
                } else if (a.find('.') != std::string::npos && dev.ipv4 == "n/a") {
                    if (a != "127.0.0.1")
                        dev.ipv4 = a;
                }
            }
        }
    }

    if (dev.ipv4 != "n/a") {
        ARPInfo arp = get_arp_info(dev.ipv4);
        dev.mac    = arp.mac.empty() ? "n/a" : normalise_mac(arp.mac);
        dev.ttl    = arp.ttl.empty() ? "n/a" : arp.ttl;
        dev.vendor = lookup_vendor(dev.mac);
    }

    if (dev.mac == "n/a") {
        struct ifaddrs* ifap;
        if (getifaddrs(&ifap) == 0) {
            for (struct ifaddrs* ifa = ifap; ifa; ifa = ifa->ifa_next) {
                if (!ifa->ifa_addr) continue;
                if (ifa->ifa_addr->sa_family == AF_LINK) {
                    std::string ifname(ifa->ifa_name);
                    if (ifname == "lo0") continue;
                    struct sockaddr_dl* sdl = (struct sockaddr_dl*)ifa->ifa_addr;
                    if (sdl->sdl_alen == 6) {
                        unsigned char* mac = (unsigned char*)LLADDR(sdl);
                        char mac_str[18];
                        snprintf(mac_str, sizeof(mac_str),
                                 "%02X:%02X:%02X:%02X:%02X:%02X",
                                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                        dev.mac    = mac_str;
                        dev.vendor = lookup_vendor(dev.mac);
                        break;
                    }
                }
            }
            freeifaddrs(ifap);
        }
    }

    return dev;
}

std::vector<NetworkDevice> scan_ips(const std::vector<std::string>& ips,
                                     unsigned int concurrency) {
    std::vector<NetworkDevice> results(ips.size());
    std::atomic<size_t> next(0);
    std::mutex err_mtx;

    auto worker = [&]() {
        for (;;) {
            size_t idx = next.fetch_add(1);
            if (idx >= ips.size()) break;
            results[idx] = get_device_info(ips[idx], true);
            if (results[idx].online) {
                std::lock_guard<std::mutex> lk(err_mtx);
                std::cerr << "  Found: " << ips[idx] << "\n";
            }
        }
    };

    unsigned int nthreads = std::min((unsigned int)ips.size(), concurrency);
    std::vector<std::thread> threads;
    threads.reserve(nthreads);
    for (unsigned int i = 0; i < nthreads; ++i)
        threads.emplace_back(worker);
    for (auto& t : threads) t.join();

    return results;
}

std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> out;
    std::stringstream ss(s);
    std::string tok;
    while (std::getline(ss, tok, delim))
        if (!tok.empty()) out.push_back(tok);
    return out;
}

uint32_t ip_to_u32(const std::string& ip) {
    struct in_addr a{};
    inet_pton(AF_INET, ip.c_str(), &a);
    return ntohl(a.s_addr);
}

std::string u32_to_ip(uint32_t v) {
    struct in_addr a{};
    a.s_addr = htonl(v);
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return buf;
}

std::vector<std::string> ips_from_subnet(const std::string& cidr) {
    auto slash = cidr.find('/');
    if (slash == std::string::npos) {
        std::cerr << "Error: invalid subnet format (expected x.x.x.x/prefix)\n";
        return {};
    }
    std::string base_ip = cidr.substr(0, slash);
    int prefix = std::stoi(cidr.substr(slash + 1));
    if (prefix < 0 || prefix > 32) {
        std::cerr << "Error: prefix must be 0-32\n";
        return {};
    }
    uint32_t mask    = prefix == 0 ? 0 : (~0u << (32 - prefix));
    uint32_t network = ip_to_u32(base_ip) & mask;
    uint32_t bcast   = network | ~mask;
    uint32_t first   = (prefix < 31) ? network + 1 : network;
    uint32_t last    = (prefix < 31) ? bcast  - 1 : bcast;
    std::vector<std::string> ips;
    for (uint32_t ip = first; ip <= last; ++ip)
        ips.push_back(u32_to_ip(ip));
    return ips;
}

std::vector<std::string> ips_from_range(const std::string& min_ip,
                                         const std::string& max_ip) {
    uint32_t lo = ip_to_u32(min_ip);
    uint32_t hi = ip_to_u32(max_ip);
    if (lo > hi) {
        std::cerr << "Error: range min IP must be <= max IP\n";
        return {};
    }
    std::vector<std::string> ips;
    for (uint32_t ip = lo; ip <= hi; ++ip)
        ips.push_back(u32_to_ip(ip));
    return ips;
}

#pragma once
#include <string>
#include <vector>
#include <map>

struct NetworkDevice {
    std::string ipv4 = "n/a";
    std::string ipv6 = "n/a";
    std::string hostname = "n/a";
    std::string mac = "n/a";
    std::string vendor = "n/a";
    std::string ttl = "n/a";
    bool online = false;
    bool has_detail = false;
};

struct ARPInfo {
    std::string mac;
    std::string ttl;
};

std::string mdns_reverse_lookup(const std::string& ipv4);
std::string get_hostname_from_arp(const std::string& ip);
ARPInfo get_arp_info(const std::string& ip);
std::string normalise_mac(std::string mac);
std::string lookup_vendor(const std::string& mac);
std::string get_ipv6(const std::string& hostname);
bool is_host_reachable(const std::string& ip);
NetworkDevice get_device_info(const std::string& target_ip, bool check_online = false);
NetworkDevice get_current_device();
std::vector<NetworkDevice> scan_ips(const std::vector<std::string>& ips, unsigned int concurrency = 64);

std::vector<std::string> split(const std::string& s, char delim);
uint32_t ip_to_u32(const std::string& ip);
std::string u32_to_ip(uint32_t v);
std::vector<std::string> ips_from_subnet(const std::string& cidr);
std::vector<std::string> ips_from_range(const std::string& min_ip, const std::string& max_ip);

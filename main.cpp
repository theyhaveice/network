#include "network.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <ctime>
#include <sys/stat.h>
#include <algorithm>

static const int    CACHE_TTL_SECS = 3600;
static const char*  CACHE_PATH     = "/tmp/network_tool_cache.tsv";

static const std::string BOLD  = "\033[1m";
static const std::string RESET = "\033[0m";

struct CacheEntry {
    time_t      timestamp;
    NetworkDevice dev;
};

static std::map<std::string, CacheEntry> g_cache;

static void load_cache() {
    std::ifstream f(CACHE_PATH);
    if (!f.is_open()) return;
    std::string line;
    time_t now = time(nullptr);
    while (std::getline(f, line)) {
        std::vector<std::string> cols = split(line, '\t');
        if (cols.size() < 8) continue;
        time_t ts = (time_t)std::stoll(cols[0]);
        if (now - ts > CACHE_TTL_SECS) continue;
        CacheEntry e;
        e.timestamp      = ts;
        e.dev.ipv4       = cols[1];
        e.dev.hostname   = cols[2];
        e.dev.ipv6       = cols[3];
        e.dev.mac        = cols[4];
        e.dev.vendor     = cols[5];
        e.dev.ttl        = cols[6];
        e.dev.online     = cols[7] == "1";
        e.dev.has_detail = (e.dev.hostname != "n/a" || e.dev.ipv6 != "n/a" ||
                            e.dev.mac != "n/a"      || e.dev.vendor != "n/a");
        g_cache[e.dev.ipv4] = e;
    }
}

static void save_cache() {
    std::ofstream f(CACHE_PATH, std::ios::trunc);
    if (!f.is_open()) return;
    time_t now = time(nullptr);
    for (auto& kv : g_cache) {
        if (now - kv.second.timestamp > CACHE_TTL_SECS) continue;
        if (!kv.second.dev.online) continue;
        const NetworkDevice& d = kv.second.dev;
        f << kv.second.timestamp << '\t'
          << d.ipv4              << '\t'
          << d.hostname          << '\t'
          << d.ipv6              << '\t'
          << d.mac               << '\t'
          << d.vendor            << '\t'
          << d.ttl               << '\t'
          << (d.online ? "1" : "0") << '\n';
    }
}

static bool cache_get(const std::string& ip, NetworkDevice& out) {
    auto it = g_cache.find(ip);
    if (it == g_cache.end()) return false;
    if (time(nullptr) - it->second.timestamp > CACHE_TTL_SECS) {
        g_cache.erase(it);
        return false;
    }
    out = it->second.dev;
    return true;
}

static void cache_put(const NetworkDevice& dev) {
    if (!dev.online) return;
    CacheEntry e;
    e.timestamp = time(nullptr);
    e.dev       = dev;
    g_cache[dev.ipv4] = e;
}

static std::string xml_escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '&':  out += "&amp;";  break;
            case '<':  out += "&lt;";   break;
            case '>':  out += "&gt;";   break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&apos;"; break;
            default:   out += c;
        }
    }
    return out;
}

static std::string json_escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;
        }
    }
    return out;
}

static std::string get_field(const NetworkDevice& dev, const std::string& field) {
    if (field == "hostname")   return dev.hostname;
    if (field == "ipv4")       return dev.ipv4;
    if (field == "ipv6")       return dev.ipv6;
    if (field == "macaddress") return dev.mac;
    if (field == "vendor")     return dev.vendor;
    if (field == "ttl")        return dev.ttl;
    return "";
}

static void print_plain(const std::vector<NetworkDevice>& devices,
                         const std::vector<std::string>& fields) {
    for (size_t i = 0; i < devices.size(); ++i) {
        if (devices.size() > 1) std::cout << "[" << devices[i].ipv4 << "]\n";
        for (const auto& f : fields) {
            if (fields.size() > 1) std::cout << f << ": ";
            std::cout << get_field(devices[i], f) << "\n";
        }
        if (devices.size() > 1 && i + 1 < devices.size()) std::cout << "\n";
    }
}

static void print_xml(const std::vector<NetworkDevice>& devices,
                       const std::vector<std::string>& fields) {
    std::cout << "<devices>\n";
    for (const auto& dev : devices) {
        std::cout << "    <device>\n";
        for (const auto& f : fields)
            std::cout << "        <" << f << ">"
                      << xml_escape(get_field(dev, f))
                      << "</" << f << ">\n";
        std::cout << "    </device>\n";
    }
    std::cout << "</devices>\n";
}

static void print_json(const std::vector<NetworkDevice>& devices,
                        const std::vector<std::string>& fields) {
    std::cout << "{\n  \"devices\": [\n";
    for (size_t i = 0; i < devices.size(); ++i) {
        std::cout << "    {\n";
        for (size_t j = 0; j < fields.size(); ++j) {
            std::cout << "      \"" << fields[j] << "\": \""
                      << json_escape(get_field(devices[i], fields[j])) << "\"";
            if (j + 1 < fields.size()) std::cout << ",";
            std::cout << "\n";
        }
        std::cout << "    }";
        if (i + 1 < devices.size()) std::cout << ",";
        std::cout << "\n";
    }
    std::cout << "  ]\n}\n";
}

static void print_main_help() {
    std::cout << "\n";
    std::cout << BOLD << "Usage:" << RESET << "\n";
    std::cout << "      network [command]\n";
    std::cout << "\n";
    std::cout << BOLD << "Commands:" << RESET << "\n";
    std::cout << "      get           Resolve and display info for one or more IP addresses\n";
    std::cout << "      current       Show network info for this device\n";
    std::cout << "      clear-cache   Delete all cached device results\n";
    std::cout << "      help          Show this help message\n";
    std::cout << "\n";
    std::cout << BOLD << "Flags:" << RESET << "\n";
    std::cout << "      --xml         Output results as XML\n";
    std::cout << "      --json        Output results as JSON\n";
    std::cout << "      --R           Show all responding devices (including bare IPs)\n";
    std::cout << "      --A           Show all devices including non-responding\n";
    std::cout << "      --nocache     Skip cache read/write for this run\n";
    std::cout << "\n";
    std::cout << "Use " << BOLD << "network [command] --help" << RESET
              << " for command-specific details.\n\n";
}

static void print_get_help() {
    std::cout << "\n";
    std::cout << BOLD << "Usage:" << RESET << "\n";
    std::cout << "      network get [flags]\n";
    std::cout << "\n";
    std::cout << BOLD << "Input flags:" << RESET << "\n";
    std::cout << "      -ip <ip>[,<ip>...]        One or more individual IP addresses\n";
    std::cout << "      -subnet <ip/prefix>       All host IPs in a CIDR subnet  (e.g. 192.168.1.0/24)\n";
    std::cout << "      -range <minIp>,<maxIp>    Inclusive IP range              (e.g. 192.168.1.1,192.168.1.64)\n";
    std::cout << "\n";
    std::cout << BOLD << "Output flags:" << RESET << "\n";
    std::cout << "      -o <field>[,<field>...]   Fields to display (default: all)\n";
    std::cout << "                                  hostname, ipv4, ipv6, macaddress, vendor, ttl\n";
    std::cout << "      --xml                     Output as XML\n";
    std::cout << "      --json                    Output as JSON\n";
    std::cout << "\n";
    std::cout << BOLD << "Filter flags:" << RESET << "\n";
    std::cout << "      --R                       Include all responding devices (even bare IPs with no hostname)\n";
    std::cout << "      --A                       Include every IP in range, responding or not\n";
    std::cout << "\n";
    std::cout << BOLD << "Cache flags:" << RESET << "\n";
    std::cout << "      --nocache                 Skip cache for this run (always re-probe)\n";
    std::cout << "\n";
    std::cout << BOLD << "Examples:" << RESET << "\n";
    std::cout << "      network get -ip 192.168.1.1\n";
    std::cout << "      network get -ip 192.168.1.1,192.168.1.2 -o hostname,ipv4 --json\n";
    std::cout << "      network get -subnet 192.168.1.0/24 --R\n";
    std::cout << "      network get -range 192.168.1.1,192.168.1.50 --xml\n\n";
}

static void print_current_help() {
    std::cout << "\n";
    std::cout << BOLD << "Usage:" << RESET << "\n";
    std::cout << "      network current [flags]\n";
    std::cout << "\n";
    std::cout << "      Displays the network information for the machine running this command.\n";
    std::cout << "      Resolves hostname, IPv4, IPv6, MAC address, and vendor from local interfaces.\n";
    std::cout << "\n";
    std::cout << BOLD << "Output flags:" << RESET << "\n";
    std::cout << "      -o <field>[,<field>...]   Fields: hostname, ipv4, ipv6, macaddress, vendor, ttl\n";
    std::cout << "      --xml                     Output as XML\n";
    std::cout << "      --json                    Output as JSON\n\n";
}

static void print_clear_cache_help() {
    std::cout << "\n";
    std::cout << BOLD << "Usage:" << RESET << "\n";
    std::cout << "      network clear-cache\n";
    std::cout << "\n";
    std::cout << "      Deletes the on-disk cache file at " << CACHE_PATH << ".\n";
    std::cout << "      Cache entries expire automatically after 1 hour.\n";
    std::cout << "      Non-responding devices are never written to cache.\n\n";
}

static int cmd_clear_cache() {
    if (remove(CACHE_PATH) == 0)
        std::cout << "Cache cleared: " << CACHE_PATH << "\n";
    else
        std::cout << "No cache file found (nothing to clear).\n";
    return 0;
}

static int cmd_current(int argc, char* argv[]) {
    std::vector<std::string> fields;
    bool xml_mode  = false;
    bool json_mode = false;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help") { print_current_help(); return 0; }
        else if (arg == "-o"     && i + 1 < argc) fields = split(argv[++i], ',');
        else if (arg == "--xml")  xml_mode  = true;
        else if (arg == "--json") json_mode = true;
    }

    if (fields.empty())
        fields = { "hostname", "ipv4", "ipv6", "macaddress", "vendor", "ttl" };

    NetworkDevice dev = get_current_device();
    std::vector<NetworkDevice> devices = { dev };

    if      (json_mode) print_json(devices, fields);
    else if (xml_mode)  print_xml(devices, fields);
    else                print_plain(devices, fields);
    return 0;
}

static int cmd_get(int argc, char* argv[]) {
    std::string              ip_arg, subnet_arg, range_arg;
    std::vector<std::string> fields;
    bool xml_mode  = false;
    bool json_mode = false;
    bool show_raw  = false;
    bool show_all  = false;
    bool no_cache  = false;
    bool scan_mode = false;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if      (arg == "--help")                    { print_get_help(); return 0; }
        else if (arg == "-ip"     && i + 1 < argc)   ip_arg     = argv[++i];
        else if (arg == "-subnet" && i + 1 < argc) { subnet_arg = argv[++i]; scan_mode = true; }
        else if (arg == "-range"  && i + 1 < argc) { range_arg  = argv[++i]; scan_mode = true; }
        else if (arg == "-o"      && i + 1 < argc)   fields = split(argv[++i], ',');
        else if (arg == "--xml")    xml_mode  = true;
        else if (arg == "--json")   json_mode = true;
        else if (arg == "--R")      show_raw  = true;
        else if (arg == "--A")      show_all  = true;
        else if (arg == "--nocache") no_cache = true;
    }

    if (ip_arg.empty() && subnet_arg.empty() && range_arg.empty()) {
        std::cerr << "Error: provide at least one of -ip, -subnet, or -range\n";
        std::cerr << "Run 'network get --help' for usage.\n";
        return 1;
    }

    if (fields.empty())
        fields = { "hostname", "ipv4", "ipv6", "macaddress", "vendor", "ttl" };

    const std::vector<std::string> valid = {
        "hostname","ipv4","ipv6","macaddress","vendor","ttl"
    };
    for (const auto& f : fields) {
        bool ok = false;
        for (const auto& v : valid) if (f == v) { ok = true; break; }
        if (!ok) { std::cerr << "Unknown field: " << f << "\n"; return 1; }
    }

    std::vector<std::string> all_ips;

    if (!ip_arg.empty())
        for (auto& ip : split(ip_arg, ','))
            all_ips.push_back(ip);

    if (!subnet_arg.empty()) {
        auto s = ips_from_subnet(subnet_arg);
        if (s.empty()) return 1;
        all_ips.insert(all_ips.end(), s.begin(), s.end());
    }

    if (!range_arg.empty()) {
        auto parts = split(range_arg, ',');
        if (parts.size() != 2) {
            std::cerr << "Error: -range expects <minIp>,<maxIp>\n";
            return 1;
        }
        auto r = ips_from_range(parts[0], parts[1]);
        if (r.empty()) return 1;
        all_ips.insert(all_ips.end(), r.begin(), r.end());
    }

    if (!no_cache) load_cache();

    std::vector<NetworkDevice> devices;

    auto resolve = [&](const std::string& ip) -> NetworkDevice {
        NetworkDevice cached;
        if (!no_cache && cache_get(ip, cached)) return cached;
        NetworkDevice d = get_device_info(ip, scan_mode || all_ips.size() > 1);
        if (!no_cache) cache_put(d);
        return d;
    };

    if (scan_mode || all_ips.size() > 1) {
        if (scan_mode)
            std::cerr << "Scanning " << all_ips.size() << " addresses...\n";

        std::vector<std::string> to_probe;
        std::map<std::string, NetworkDevice> from_cache;

        if (!no_cache) {
            for (const auto& ip : all_ips) {
                NetworkDevice cached;
                if (cache_get(ip, cached)) from_cache[ip] = cached;
                else to_probe.push_back(ip);
            }
        } else {
            to_probe = all_ips;
        }

        auto probed_raw = scan_ips(to_probe);
        for (auto& d : probed_raw) {
            if (!no_cache) cache_put(d);
        }

        for (const auto& ip : all_ips) {
            NetworkDevice d;
            auto it = from_cache.find(ip);
            if (it != from_cache.end()) {
                d = it->second;
            } else {
                for (auto& pd : probed_raw)
                    if (pd.ipv4 == ip) { d = pd; break; }
            }

            if (show_all)          { devices.push_back(d); continue; }
            if (!d.online)         continue;
            if (show_raw)          { devices.push_back(d); continue; }
            if (d.has_detail)      devices.push_back(d);
        }

        if (scan_mode)
            std::cerr << "Showing " << devices.size() << " device(s).\n\n";

    } else {
        NetworkDevice d = resolve(all_ips[0]);
        devices.push_back(d);
    }

    if (!no_cache) save_cache();

    if      (json_mode) print_json(devices, fields);
    else if (xml_mode)  print_xml(devices, fields);
    else                print_plain(devices, fields);

    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) { print_main_help(); return 0; }

    std::string cmd = argv[1];

    if (cmd == "help"        || cmd == "--help") { print_main_help();        return 0; }
    if (cmd == "clear-cache")                    { return cmd_clear_cache();          }
    if (cmd == "current")                        { return cmd_current(argc, argv);    }
    if (cmd == "get")                            { return cmd_get(argc, argv);        }

    std::cerr << "Unknown command: " << cmd << "\n";
    std::cerr << "Run 'network help' to see available commands.\n";
    return 1;
}

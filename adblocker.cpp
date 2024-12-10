#include <pcap.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <iostream>
#include <string>
#include <unordered_set>

// Ad domains to block
std::unordered_set<std::string> blockedDomains = {
    "ads.google.com",
    "trackers.google.com",
    "doubleclick.net"
};

// Callback function to process packets
void packetHandler(u_char* user, const struct pcap_pkthdr* pktHeader, const u_char* pktData) {
    const u_char* payload = pktData + 42; // DNS starts after Ethernet (14), IP (20), and UDP (8)
    std::string domain(reinterpret_cast<const char*>(payload + 12)); // Extract domain from DNS query
    
    // Check if domain is blocked
    for (const auto& blocked : blockedDomains) {
        if (domain.find(blocked) != std::string::npos) {
            std::cout << "Blocked: " << domain << std::endl;
            return; // Drop the packet
        }
    }
    std::cout << "Allowed: " << domain << std::endl;
}

int main() {
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Find available network devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }

    pcap_if_t* device = alldevs; // Select the first device (you can expand this to choose a specific one)
    pcap_t* handle = pcap_open_live(device->name, 65536, 1, 1000, errbuf);
    
    if (handle == nullptr) {
        std::cerr << "Failed to open device: " << errbuf << std::endl;
        return 1;
    }
    
    // Start packet capture loop
    pcap_loop(handle, 0, packetHandler, nullptr);

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}

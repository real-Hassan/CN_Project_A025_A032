#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <iostream>
#include <vector>
#include <iomanip>
#include <sstream>

#pragma comment(lib, "ws2_32.lib")

#ifndef SIO_RCVALL
#define SIO_RCVALL _WSAIOW(IOC_VENDOR, 1)
#endif

// ── Layer 3: IPv4 Header ─────────────────────────────────────
struct IPHeader {
    unsigned char  iph_ihl:4, iph_ver:4;
    unsigned char  iph_tos;
    unsigned short iph_len;
    unsigned short iph_id;
    unsigned short iph_offset;
    unsigned char  iph_ttl;
    unsigned char  iph_protocol;
    unsigned short iph_chksum;
    unsigned int   iph_src;
    unsigned int   iph_dest;
};

// ── Layer 4: TCP Header ──────────────────────────────────────
struct TCPHeader {
    unsigned short src_port;
    unsigned short dest_port;
    unsigned int   seq_num;
    unsigned int   ack_num;
    unsigned short data_offset:4, reserved:6, ctrl_flags:6;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_ptr;
};

// ── Layer 4: UDP Header ──────────────────────────────────────
struct UDPHeader {
    unsigned short src_port;
    unsigned short dest_port;
    unsigned short len;
    unsigned short checksum;
};

// ── Helper: IP as dotted string ──────────────────────────────
std::string ipToStr(unsigned int ip) {
    struct in_addr a;
    a.s_addr = ip;
    return std::string(inet_ntoa(a));
}

// ── Helper: IP as hex string ─────────────────────────────────
std::string ipToHex(unsigned int ip) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase
        << std::setfill('0') << std::setw(8) << ntohl(ip);
    return oss.str();
}

// ── Helper: 16-bit value as hex string ──────────────────────
std::string u16ToHex(unsigned short val) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase
        << std::setfill('0') << std::setw(4) << val;
    return oss.str();
}

// ── Helper: 32-bit value as hex string ──────────────────────
std::string u32ToHex(unsigned int val) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase
        << std::setfill('0') << std::setw(8) << val;
    return oss.str();
}

// ── Helper: TCP checksum verification ───────────────────────
// Returns the computed checksum over the TCP pseudo-header + segment.
// If it equals 0x0000 the checksum is valid.
unsigned short computeTCPChecksum(const IPHeader* iph, const TCPHeader* tcph, int tcp_seg_len) {
    // Pseudo-header
    struct {
        unsigned int  src;
        unsigned int  dst;
        unsigned char zero;
        unsigned char proto;
        unsigned short tcp_len;
    } pseudo;

    pseudo.src     = iph->iph_src;
    pseudo.dst     = iph->iph_dest;
    pseudo.zero    = 0;
    pseudo.proto   = 6;
    pseudo.tcp_len = htons((unsigned short)tcp_seg_len);

    unsigned long sum = 0;

    // Sum pseudo-header
    const unsigned short* p = (const unsigned short*)&pseudo;
    for (int i = 0; i < (int)sizeof(pseudo) / 2; i++) sum += ntohs(p[i]);

    // Sum TCP segment (with checksum field treated as 0)
    const unsigned short* t = (const unsigned short*)tcph;
    for (int i = 0; i < tcp_seg_len / 2; i++) {
        if (i == 8) { sum += 0; continue; }  // skip checksum field (offset 16 bytes = word 8)
        sum += ntohs(t[i]);
    }
    if (tcp_seg_len & 1)   // odd byte
        sum += ((const unsigned char*)tcph)[tcp_seg_len - 1] << 8;

    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (unsigned short)(~sum & 0xFFFF);
}

// ── Helper: UDP checksum verification ───────────────────────
unsigned short computeUDPChecksum(const IPHeader* iph, const UDPHeader* udph, int udp_len) {
    struct {
        unsigned int   src;
        unsigned int   dst;
        unsigned char  zero;
        unsigned char  proto;
        unsigned short udp_len;
    } pseudo;

    pseudo.src     = iph->iph_src;
    pseudo.dst     = iph->iph_dest;
    pseudo.zero    = 0;
    pseudo.proto   = 17;
    pseudo.udp_len = htons((unsigned short)udp_len);

    unsigned long sum = 0;

    const unsigned short* p = (const unsigned short*)&pseudo;
    for (int i = 0; i < (int)sizeof(pseudo) / 2; i++) sum += ntohs(p[i]);

    const unsigned short* u = (const unsigned short*)udph;
    for (int i = 0; i < udp_len / 2; i++) {
        if (i == 3) { sum += 0; continue; }  // skip checksum field (offset 6 bytes = word 3)
        sum += ntohs(u[i]);
    }
    if (udp_len & 1)
        sum += ((const unsigned char*)udph)[udp_len - 1] << 8;

    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (unsigned short)(~sum & 0xFFFF);
}

// ── Helper: IPv4 header checksum verification ────────────────
unsigned short computeIPChecksum(const IPHeader* iph) {
    int ip_hlen = iph->iph_ihl * 4;
    unsigned long sum = 0;
    const unsigned short* w = (const unsigned short*)iph;
    for (int i = 0; i < ip_hlen / 2; i++) {
        if (i == 5) { sum += 0; continue; }  // skip existing checksum word
        sum += ntohs(w[i]);
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (unsigned short)(~sum & 0xFFFF);
}

// ── Helper: Escape a string for JSON ────────────────────────
std::string jsonEscape(const std::string& s) {
    std::ostringstream out;
    for (unsigned char c : s) {
        if      (c == '"')  out << "\\\"";
        else if (c == '\\') out << "\\\\";
        else if (c == '\n') out << "\\n";
        else if (c == '\r') out << "\\r";
        else if (c == '\t') out << "\\t";
        else if (c < 0x20)  out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
        else                out << c;
    }
    return out.str();
}

// ── Helper: Build hex/ASCII payload string ───────────────────
std::string buildPayloadString(const char* data, int size) {
    if (size <= 0) return "";
    std::ostringstream out;
    for (int i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0) {
            out << "  ";
            for (int j = i - 16; j < i; j++)
                out << (char)(isprint((unsigned char)data[j]) ? data[j] : '.');
            out << "\\n";
        }
        out << std::hex << std::setw(2) << std::setfill('0')
            << (int)(unsigned char)data[i] << " ";
        if (i == size - 1) {
            for (int k = 0; k < (15 - (i % 16)); k++) out << "   ";
            out << "  ";
            for (int j = i - (i % 16); j <= i; j++)
                out << (char)(isprint((unsigned char)data[j]) ? data[j] : '.');
        }
    }
    return out.str();
}

// ── Pretty divider for terminal ──────────────────────────────
void printDiv() {
    std::cout << "  " << std::string(60, '-') << std::endl;
}

int main() {
    WSADATA wsa;
    SOCKET  rawSock;
    char    hostname[255];
    struct  hostent* local;
    struct  sockaddr_in sa;
    int     optval    = 1;
    DWORD   dwBytesRet = 0;

    std::cout << "=== CN Project: Advanced Packet Sniffer ===" << std::endl;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;

    rawSock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (rawSock == INVALID_SOCKET) {
        std::cerr << "Socket Error: " << WSAGetLastError()
                  << "  (Run as Administrator!)" << std::endl;
        return 1;
    }

    gethostname(hostname, sizeof(hostname));
    local = gethostbyname(hostname);
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(0);
    memcpy(&sa.sin_addr.S_un.S_addr,
           local->h_addr_list[0],
           sizeof(sa.sin_addr.S_un.S_addr));

    if (bind(rawSock, (struct sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR) {
        std::cerr << "Bind Error: " << WSAGetLastError() << std::endl;
        return 1;
    }

    if (WSAIoctl(rawSock, SIO_RCVALL, &optval, sizeof(optval),
                 NULL, 0, &dwBytesRet, NULL, NULL) == SOCKET_ERROR) {
        std::cerr << "WSAIoctl Error: " << WSAGetLastError()
                  << "  (Need Admin rights)" << std::endl;
        return 1;
    }

    std::string ifaceIP = inet_ntoa(sa.sin_addr);
    std::cout << "Sniffing on: " << ifaceIP << "\n" << std::endl;

    std::vector<char> buffer(65536);

    while (true) {
        int size = recv(rawSock, buffer.data(), (int)buffer.size(), 0);
        if (size <= 0) continue;

        IPHeader* iph   = (IPHeader*)buffer.data();
        int       ip_hl = iph->iph_ihl * 4;

        // ── Compute & verify IP checksum ─────────────────────
        unsigned short ip_chksum_wire = ntohs(iph->iph_chksum);
        unsigned short ip_chksum_calc = computeIPChecksum(iph);
        bool           ip_chk_ok      = (ip_chksum_calc == 0x0000);

        // ── Human-readable terminal output ───────────────────
        std::cout << "\n[IPv4]" << std::endl;
        std::cout << "  Src IP   : " << ipToStr(iph->iph_src)
                  << "  (" << ipToHex(iph->iph_src) << ")" << std::endl;
        std::cout << "  Dst IP   : " << ipToStr(iph->iph_dest)
                  << "  (" << ipToHex(iph->iph_dest) << ")" << std::endl;
        std::cout << "  TTL      : " << std::dec << (int)iph->iph_ttl << std::endl;
        std::cout << "  IP Chksum: " << u16ToHex(ip_chksum_wire)
                  << "  [" << (ip_chk_ok ? "VALID" : "INVALID") << "]" << std::endl;
        printDiv();

        int    transport_len = 0;
        std::string protocol  = "OTHER";

        // Fields that go into JSON
        unsigned short src_port  = 0, dst_port  = 0;
        unsigned short t_chksum_wire = 0;
        unsigned short t_chksum_calc = 0;
        bool           t_chk_ok      = false;
        unsigned int   seq_num = 0, ack_num = 0;

        // ── TCP ──────────────────────────────────────────────
        if (iph->iph_protocol == 6) {
            protocol = "TCP";
            TCPHeader* tcph = (TCPHeader*)(buffer.data() + ip_hl);
            transport_len   = tcph->data_offset * 4;

            src_port       = ntohs(tcph->src_port);
            dst_port       = ntohs(tcph->dest_port);
            seq_num        = ntohl(tcph->seq_num);
            ack_num        = ntohl(tcph->ack_num);
            t_chksum_wire  = ntohs(tcph->checksum);

            int tcp_seg_len = size - ip_hl;
            t_chksum_calc   = computeTCPChecksum(iph, tcph, tcp_seg_len);
            t_chk_ok        = (t_chksum_calc == 0x0000);

            std::cout << "[TCP]" << std::endl;
            std::cout << "  Src Port : " << std::dec << src_port
                      << "  (" << u16ToHex(src_port) << ")" << std::endl;
            std::cout << "  Dst Port : " << std::dec << dst_port
                      << "  (" << u16ToHex(dst_port) << ")" << std::endl;
            std::cout << "  Seq Num  : " << std::dec << seq_num
                      << "  (" << u32ToHex(seq_num) << ")" << std::endl;
            std::cout << "  Ack Num  : " << std::dec << ack_num
                      << "  (" << u32ToHex(ack_num) << ")" << std::endl;
            std::cout << "  Checksum : " << u16ToHex(t_chksum_wire)
                      << "  [" << (t_chk_ok ? "VALID" : "INVALID") << "]" << std::endl;
            std::cout << "  Total    : " << std::dec << size << " bytes" << std::endl;
        }

        // ── UDP ──────────────────────────────────────────────
        else if (iph->iph_protocol == 17) {
            protocol = "UDP";
            UDPHeader* udph = (UDPHeader*)(buffer.data() + ip_hl);
            transport_len   = 8;

            src_port      = ntohs(udph->src_port);
            dst_port      = ntohs(udph->dest_port);
            t_chksum_wire = ntohs(udph->checksum);

            int udp_len   = ntohs(udph->len);
            t_chksum_calc = computeUDPChecksum(iph, udph, udp_len);
            t_chk_ok      = (t_chksum_calc == 0x0000 || t_chksum_wire == 0x0000); // 0x0000 means disabled in UDP

            std::cout << "[UDP]" << std::endl;
            std::cout << "  Src Port : " << std::dec << src_port
                      << "  (" << u16ToHex(src_port) << ")" << std::endl;
            std::cout << "  Dst Port : " << std::dec << dst_port
                      << "  (" << u16ToHex(dst_port) << ")" << std::endl;
            std::cout << "  Checksum : " << u16ToHex(t_chksum_wire)
                      << "  [" << (t_chk_ok ? "VALID" : "INVALID") << "]" << std::endl;
            std::cout << "  Total    : " << std::dec << size << " bytes" << std::endl;
        }

        // ── ICMP / Other ─────────────────────────────────────
        else {
            protocol = (iph->iph_protocol == 1) ? "ICMP" : "OTHER";
            std::cout << "[" << protocol << "]  Protocol Number: "
                      << std::dec << (int)iph->iph_protocol << std::endl;
            std::cout << "  Total    : " << std::dec << size << " bytes" << std::endl;
        }

        // ── Payload ──────────────────────────────────────────
        int payload_offset = ip_hl + transport_len;
        int payload_size   = size - payload_offset;
        std::string payloadStr = "";
        if (payload_size > 0) {
            printDiv();
            payloadStr = buildPayloadString(buffer.data() + payload_offset, payload_size);
            // Also print to terminal
            std::cout << "   Payload (" << std::dec << payload_size << " bytes):" << std::endl;
            // Re-use existing print logic inline
            const char* pdata = buffer.data() + payload_offset;
            for (int i = 0; i < payload_size; i++) {
                if (i != 0 && i % 16 == 0) {
                    std::cout << "  ";
                    for (int j = i - 16; j < i; j++)
                        std::cout << (char)(isprint((unsigned char)pdata[j]) ? pdata[j] : '.');
                    std::cout << std::endl;
                }
                std::cout << std::hex << std::setw(2) << std::setfill('0')
                          << (int)(unsigned char)pdata[i] << " ";
                if (i == payload_size - 1) {
                    for (int k = 0; k < (15 - (i % 16)); k++) std::cout << "   ";
                    std::cout << "  ";
                    for (int j = i - (i % 16); j <= i; j++)
                        std::cout << (char)(isprint((unsigned char)pdata[j]) ? pdata[j] : '.');
                    std::cout << std::endl;
                }
            }
        }
        printDiv();

        // ── Emit JSON line for server.js ──────────────────────
        // One compact JSON object per packet, terminated by newline.
        // server.js reads this line directly with readline.
        std::cout << "[JSON] {"
            << "\"src\":\""         << jsonEscape(ipToStr(iph->iph_src))  << "\","
            << "\"dest\":\""        << jsonEscape(ipToStr(iph->iph_dest)) << "\","
            << "\"src_hex\":\""     << ipToHex(iph->iph_src)              << "\","
            << "\"dst_hex\":\""     << ipToHex(iph->iph_dest)             << "\","
            << "\"protocol\":\""    << protocol                           << "\","
            << "\"ttl\":"           << std::dec << (int)iph->iph_ttl      << ","
            << "\"iface\":\""       << jsonEscape(ifaceIP)                << "\","
            << "\"ip_checksum\":\""     << u16ToHex(ip_chksum_wire)       << "\","
            << "\"ip_checksum_valid\":" << (ip_chk_ok ? "true" : "false") << ","
            << "\"src_port\":"      << std::dec << src_port               << ","
            << "\"dest_port\":"     << std::dec << dst_port               << ","
            << "\"port\":"          << std::dec << dst_port               << ","
            << "\"checksum\":\""        << u16ToHex(t_chksum_wire)        << "\","
            << "\"checksum_valid\":"    << (t_chk_ok ? "true" : "false")  << ","
            << "\"seq\":"           << std::dec << seq_num                << ","
            << "\"seq_hex\":\""     << u32ToHex(seq_num)                  << "\","
            << "\"ack\":"           << std::dec << ack_num                << ","
            << "\"ack_hex\":\""     << u32ToHex(ack_num)                  << "\","
            << "\"size\":"          << std::dec << size                   << ","
            << "\"payload_size\":"  << std::dec << payload_size           << ","
            << "\"payload\":\""     << jsonEscape(payloadStr)             << "\""
            << "}" << std::endl;
    }

    WSACleanup();
    return 0;
}
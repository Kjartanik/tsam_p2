#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <iostream>
#include <unistd.h>
#include <cstdint>  // for uint8_t
#include <cstring>  // for memset and memcpy
#include <iomanip>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <errno.h>

const char* SOURCE_ADDRESS = "172.20.10.2";
const uint16_t SOURCE_PORT = 65202;

// Create structure for UDP header
struct udp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
};

// Create IPv4 header 
struct ip4_hdr {
    uint8_t ihl:4, version:4;
    unsigned int dscp:6;
    unsigned int ecn:2;
    uint16_t tot_len; // Should be 5 with no options
    uint16_t id;
    unsigned int flags:3;
    unsigned int frag_offset:13;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
    // Skip options since we wont need any
};

// Made another ip header for puzzle three
struct ip_hdr {
    uint8_t version_ihl; 
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

// Create pseudo header structure for checksum calculation of udp header
struct p_hdr {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t zeros; // All zeros
    uint8_t protocol;
    uint16_t length;
};

// We'll also need a UDP header however that structure can be imported on our machine.


int solve_puzzle_1(int sockfd, char* ip_addr, int port_1) {
    // Puzzle 1: Greetings from S.E.C.R.E.T (Secure Encryption Certification Relay with Enhanced Trust)! Here's how to access the secret port I'm safeguarding:
    // 1. Send me your group number as a single unsigned byte.
    // 2. I'll reply with a 4-byte challenge (in network byte order) unique to your group.
    // 3. Sign this challenge using the XOR operation with your group's secret (get that from your TA).
    // 4. Reply with a 5-byte message: the first byte is your group number, followed by the 4-byte signed challenge (in network byte order).
    // 5. If your signature is correct, I'll grant you access to the port. Good luck!

     // Setup server address with port 1
    struct sockaddr_in server_addr_1;
    memset(&server_addr_1, 0, sizeof(server_addr_1));
    server_addr_1.sin_family = AF_INET;
    server_addr_1.sin_port = htons(port_1);

    // Check if IP is valid
    if (inet_pton(AF_INET, ip_addr, &server_addr_1.sin_addr) <= 0) {
        std::cerr << "Invalid IP address provided." << std::endl;
        close(sockfd);
        return -1;
    }

    // Send group number as unsigned int, 8 bits long, to the server.
    std::uint8_t group_number = 47;
    if (sendto(sockfd, &group_number, 1, 0, (struct sockaddr*)&server_addr_1, sizeof(server_addr_1)) < 0) {
        std::cerr << "Failed to send group number to server." << std::endl;
        close(sockfd);
        return -1;
    }

    // Create file descriptor set for select
    fd_set read_fds;
    FD_ZERO(&read_fds);
    // Add socket to the FD set
    FD_SET(sockfd, &read_fds);

    // Timeout settings
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;


    int ready_to_read = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);
    if (ready_to_read > 0) {
        struct sockaddr_in recv_addr;
        socklen_t recv_len = sizeof(recv_addr);
        std::uint32_t challenge;

        int received_bytes = recvfrom(sockfd, &challenge, sizeof(challenge), 0, (struct sockaddr*)&recv_addr, &recv_len);
        if (received_bytes > 0) {
            std::cout << "Port: " << port_1 << " is open. Challenge received: " << std::hex << challenge << std::dec << std::endl;
        } else {
            std::cerr << "Failed to receive challenge from server." << std::endl;
            close(sockfd);
            return -1;
        }

        // Sign challenge with group secret
        uint32_t secret = 0xc09182f1; // Group secret reversed
        uint32_t signed_challenge = secret ^ challenge;
        std::cout << "Signed challenge: " << std::hex << signed_challenge << std::endl;

        // Create the 5-byte response message with array of 5, 8 bit integers
        uint8_t response[5];
        response[0] = group_number;
        memcpy(&response[1], &signed_challenge, sizeof(signed_challenge));

        // Send the signed challenge back to the server
        if (sendto(sockfd, response, sizeof(response), 0, (struct sockaddr*)&server_addr_1, sizeof(server_addr_1)) < 0) {
            std::cerr << "Failed to send signed challenge to server." << std::endl;
            close(sockfd);
            return -1;
        }

        // Reset file descriptor set and timeout for receiving final response
        FD_ZERO(&read_fds);
        FD_SET(sockfd, &read_fds);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        ready_to_read = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);
        if (ready_to_read > 0) {
            char buffer[1024];
            received_bytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&recv_addr, &recv_len);
            if (received_bytes > 0) {
                buffer[received_bytes] = '\0';
                // Server response should be new open port.
                std::cout << "Server response: " << buffer << std::endl;
                return 1; 
            } 
            else {
                std::cout << "Failed to receive final response from server." << std::endl;
            }
        } 
        else {
            std::cout << "Socket not ready to read." << std::endl;
        }
    } 
    else {
        std::cout << "No challenge received from the server within the timeout period." << std::endl;
    }
    return -1;
}

// Calclates the check sum of a given header or package
// Package size must a mutliple of 16, which the packages in this assignment are.
uint16_t calc_checksum(char* packet, const int packet_size) {
    uint32_t sum = 0; // Use 32-bit to allow overflow
    for (size_t i = 0; i < packet_size; i += 2) {
        uint16_t bits = (static_cast<uint8_t>(packet[i]) << 8);
        if (i + 1 < packet_size) {
            bits |= static_cast<uint8_t>(packet[i + 1]);
        } else {
            bits |= 0; // Pad with zeros if odd byte
        }
        sum += bits;
        
        // Carry over
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }
    return ~static_cast<uint16_t>(sum);
}

char* create_inner_packet(uint32_t src_ip, char* dst_ip, uint16_t src_port, uint16_t dst_port, uint16_t checksum, const int packet_size) {
    char* packet = new char[packet_size];
    // Construct IP header
    struct ip4_hdr* ip_header = (struct ip4_hdr*)packet;
    ip_header->version = 0x04;
    ip_header->ihl = 5;
    ip_header->dscp = 0;
    ip_header->ecn = 0;
    ip_header->tot_len = htons(packet_size);
    ip_header->id = htons(54321);
    ip_header->flags = 0;
    ip_header->frag_offset = 0;
    ip_header->ttl = 64;
    ip_header->protocol = IPPROTO_UDP;
    ip_header->checksum = 0;
    ip_header->src_addr = htonl(src_ip);
    ip_header->dst_addr = inet_addr(dst_ip);

    // Now calculate header checksum
    uint16_t ip_header_checksum;
    ip_header_checksum = calc_checksum(packet, sizeof(struct ip4_hdr));
    ip_header->checksum = ip_header_checksum;


    // Construct UDP header 
    struct udp_hdr* udp_header = (struct udp_hdr*)(packet + sizeof(struct ip4_hdr));
    udp_header->src_port = htons(src_port);
    udp_header->dst_port = htons(dst_port);
    udp_header->len = htons(10); // UDP header length + 2 bytes for payload
    udp_header->checksum = htons(checksum);

    // Construct Pseudo header and UDP header to calculate needed payload for given checksum
    const int pseudo_packet_size = (sizeof(struct udp_hdr) + sizeof(struct p_hdr));
    char* pseudo_packet = new char[pseudo_packet_size];
    struct p_hdr* pseudo_header = (struct p_hdr*)(pseudo_packet);
    pseudo_header->src_addr = htonl(src_ip);
    pseudo_header->dst_addr = inet_addr(dst_ip);
    pseudo_header->zeros = 0;
    pseudo_header->protocol = IPPROTO_UDP;
    pseudo_header->length = htons(10); // same length as in UDP header

    // Create new Pseudo UDP header, only for checksum calculation
    struct udp_hdr* p_udp_header = (struct udp_hdr*)(pseudo_packet + sizeof(struct p_hdr));
    p_udp_header->src_port = htons(src_port);
    p_udp_header->dst_port = htons(dst_port);
    p_udp_header->len = htons(10); // UDP header length + 2 bytes for payload
    p_udp_header->checksum = 0;

    // Calculate Current UDP checksum, then calculate payload needed to make the given checksum valid.
    uint16_t udp_checksum = calc_checksum(pseudo_packet, pseudo_packet_size);
    std::cout << "Checksum of packet before adding payload: " << std::hex << udp_checksum << std::endl;
    uint16_t* payload = (uint16_t*)(packet + sizeof(struct ip4_hdr) + sizeof(struct udp_hdr));
    
    *payload = htons((~checksum - ~udp_checksum)); // These calculations should be correct
    // However sometimes We're getting a calculated checksum from the server that is our checksum -1
    std::cout << "Calculated value of payload: " << std::hex << *payload << std::endl;
    uint16_t csum = calc_checksum(packet, packet_size);

    // Pseudo packet no longer needed
    delete[] pseudo_packet;

    return packet;
} 

int solve_puzzle_2(int sockfd, char* ip_addr, int port_2, int sig) {
    // Send me a 4-byte message containing the signature you got from S.E.C.R.E.T 
    // in the first 4 bytes (in network byte order)
    struct sockaddr_in server_addr_2;
    memset(&server_addr_2, 0, sizeof(server_addr_2));
    server_addr_2.sin_family = AF_INET;
    server_addr_2.sin_port = htons(port_2);

    // Check if IP is valid
    if (inet_pton(AF_INET, ip_addr, &server_addr_2.sin_addr) <= 0) {
        std::cerr << "Invalid IP address provided." << std::endl;
        return -1;
    }

    // Send signature to the server
    if (sendto(sockfd, &sig, sizeof(sig), 0, (struct sockaddr*)&server_addr_2, sizeof(server_addr_2)) < 0) {
        std::cerr << "Failed to send signature to server." << std::endl;
        close(sockfd);
        return -1;
    }

    // Prepare for receiving response
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(sockfd, &read_fds);

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    // Check if there is a response
    int ready_to_read = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);
    if (ready_to_read > 0) {
        struct sockaddr_in recv_addr;
        socklen_t recv_len = sizeof(recv_addr);
        char buffer[1024];

        int received_bytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&recv_addr, &recv_len);
        if (received_bytes > 0) {
            std::cout << "Message from port: " << port_2 << ", received: " << buffer << std::endl;

            // Extract checksum and source IP from the last 6 bytes of the message
            uint16_t v_checksum;
            uint32_t src_ip;

            memcpy(&v_checksum, buffer + received_bytes - 6, 2);
            v_checksum = ntohs(v_checksum);
            memcpy(&src_ip, buffer + received_bytes - 4, 4);
            src_ip = ntohl(src_ip);

            std::cout << "Source IP: " << std::hex << src_ip << std::dec << std::endl;
            std::cout << "Checksum: " << std::hex << v_checksum << std::dec << std::endl;

            // Create the inner packet with a dummy payload to match the checksum
            uint16_t src_port = 61235; // Your local port
            const int inner_packet_size = sizeof(struct ip4_hdr) + sizeof(struct udp_hdr) + sizeof(uint16_t); // 16 bits for payload
            char* inner_packet = create_inner_packet(src_ip, ip_addr, src_port, port_2, v_checksum, inner_packet_size);

            // Send the inner packet
            if (sendto(sockfd, inner_packet, inner_packet_size, 0, (struct sockaddr*)&server_addr_2, sizeof(server_addr_2)) < 0) {
                std::cerr << "Failed to send encapsulated packet to server." << std::endl;
                delete[] inner_packet;
                close(sockfd);
                return -1;
            }

            delete[] inner_packet;

            // Wait for the response after sending the encapsulated packet
            timeout.tv_sec = 5;
            timeout.tv_usec = 0;

            FD_ZERO(&read_fds);
            FD_SET(sockfd, &read_fds);

            ready_to_read = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);
            if (ready_to_read > 0) {
                memset(buffer, 0, sizeof(buffer));
                received_bytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&recv_addr, &recv_len);
                if (received_bytes > 0) {
                    std::cout << "Message from port: " << port_2 << ", after sending encapsulated packet, received: " << buffer << std::endl;
                } else {
                    std::cerr << "Failed to receive response from server port:" << port_2 << std::endl;
                    return -1;
                }
            } else {
                std::cout << "No message received after sending encapsulated packet in given timeframe." << std::endl;
                return -1;
            }
        } else {
            std::cerr << "Failed to receive response from server port:" << port_2 << std::endl;
            return -1;
        }
    } else {
        std::cerr << "No response received from server within the timeout period." << std::endl;
    }
    return 1;
}


int solve_puzzle_3(int sockfd, char* dst_ip, int dst_port, int signature) {
    // Construct the source and destination addresses
    struct sockaddr_in src_addr;
    src_addr.sin_family = AF_INET;
    src_addr.sin_port = htons(SOURCE_PORT);
    inet_aton(SOURCE_ADDRESS, &src_addr.sin_addr);
    
    struct sockaddr_in dst_addr;
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(dst_port);
    inet_aton(dst_ip, &dst_addr.sin_addr);


    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sock < 0) {
        perror("Raw socket creation failed.");
        return -1;
    }
    int on = 1;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("Error setting IP_HDRINCL");
        close(raw_sock);
        return -1;
    }

    // Construct the packet to send and its size
    uint16_t packet_size = sizeof(struct ip4_hdr) + sizeof(struct udp_hdr) + 4; // 4 bytes to send, should be 30 in total
    uint16_t packet[packet_size];

    struct ip4_hdr* ip_header;
    ip_header = (struct ip4_hdr*)packet;
    ip_header->version = 4;
    ip_header->ihl = 5; // 5 when no options are set
    ip_header->dscp = 0;
    ip_header->ecn = 0;
    ip_header->tot_len = htons(packet_size)+1; // header + 4 bytes data
    ip_header->id = 0; // Should be automatic
    ip_header->flags = (1<<2) | 1;
    ip_header->frag_offset = 0;
    ip_header->ttl = 64;
    ip_header->protocol = IPPROTO_UDP;
    ip_header->checksum = 0; // should be automatic
    ip_header->src_addr = src_addr.sin_addr.s_addr;
    ip_header->dst_addr = dst_addr.sin_addr.s_addr;

    ip_header->checksum = calc_checksum((char*)ip_header, sizeof(struct ip4_hdr));

    // This should be correct for IP header
    uint16_t udp_length = sizeof(struct udp_hdr) + sizeof(int);
    // Construct udp header and pseudo header for checksum
    uint16_t pseudo_packet_size = sizeof(struct p_hdr) + sizeof(struct udp_hdr) + sizeof(int);
    uint16_t pseudo_packet[pseudo_packet_size];
    struct p_hdr* pseudo_header = (struct p_hdr *)pseudo_packet;
    pseudo_header->src_addr = src_addr.sin_addr.s_addr;
    pseudo_header->dst_addr = dst_addr.sin_addr.s_addr;
    pseudo_header->zeros = 0;
    pseudo_header->protocol = IPPROTO_UDP;
    pseudo_header->length = htons(udp_length);

    struct udp_hdr *udp_header;
    udp_header = (struct udp_hdr *)(packet + sizeof(struct p_hdr));
    udp_header->src_port = src_addr.sin_port;
    udp_header->dst_port = dst_addr.sin_port;
    udp_header->len = htons(udp_length); // UDP header + 4-byte payload
    
    int* payload;
    payload = (int*)(packet + sizeof(struct p_hdr)+ sizeof(struct udp_hdr));
    *payload = htonl(signature);

    uint16_t checksum = calc_checksum((char*)pseudo_packet, pseudo_packet_size);
    udp_header->checksum = checksum;

    memcpy(packet + sizeof(struct ip4_hdr), pseudo_packet + sizeof(struct p_hdr), sizeof(udp_hdr));

    if(sendto(raw_sock, packet, packet_size, 0, (struct sockaddr *)&dst_addr, sizeof(dst_addr)) < 0){
        std::cout << "Send to with raw socket failed" << std::endl;
        close(raw_sock);
        return -1;
    }
    std::cout << "Send with raw socket successful" << std::endl;

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(sockfd, &read_fds);

    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    std::cout << "Send with raw socket successful" << std::endl;

    int ready_to_read = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);
    if (ready_to_read <= 0) {
        std::cout << "Failed to recieve message in timeframe" << std::endl;
        close(raw_sock);
        return -1;
    }
    std::cout << "Socket ready to read" << std::endl; 
    struct sockaddr_in recv_addr;
    socklen_t recv_len = sizeof(recv_addr);
    char buffer[1024];

    int recieved_bytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&recv_addr, &recv_len);
    if (recieved_bytes < 0) {
        std::cout << "Failed to read EVIL socket" << std::endl;
        close(raw_sock);
        return -1;
    }
    std::cout << "Server response:\n" << buffer << std::endl;

    return 1;
}



int main(int argc, char *argv[]) {
    // Check argument count
    if (argc != 6) {
        std::cout << "Incorrect number of arguments: Should be 5." << std::endl;
        return 1;
    }

    char* ip_addr = argv[1];
    int port_1, port_2, port_3, port_4;

    // Convert ports 1-4 to integers and validate them
    try {
        port_1 = std::stoi(argv[2]);
        port_2 = std::stoi(argv[3]);
        port_3 = std::stoi(argv[4]);
        port_4 = std::stoi(argv[5]);
    }
    catch (std::invalid_argument& e) {
        std::cout << "All ports must be a number." << std::endl;
        exit(1);
    } 
    catch (std::out_of_range& e) {
        std::cout << "All ports must be a number between 0 and 65535." << std::endl;
        exit(1);
    }
    if (port_1 < 1 || port_1 > 65535 || 
        port_2 < 1 || port_2 > 65535 || 
        port_3 < 1 || port_3 > 65535 ||
        port_4 < 1 || port_4 > 65535) {
        std::cout << "All ports must be a number between 0 and 65535" << std::endl;
        exit(1);
    }


    // Create socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::cout << "Failed to create socket." << std::endl;
        return 1;
    }


    // Solve puzzle 1:
    int solved_1 = solve_puzzle_1(sockfd, ip_addr, port_1);
    if (solved_1 < 0) {
        std::cout << "Failed to solve puzzle 1" << std::endl;
    }
    // Puzzle solved port: 4045, signiture 3293dd49
    int signature = 0x3293dd49;

    int solved_2 = solve_puzzle_2(sockfd, ip_addr, port_2, signature);
    if (solved_2 < 0) {
        std::cout << "Failed to solve puzzle 2" << std::endl;
    }

    // Pass Phrase: Omae wa mou shindeiru

    int solved_3 = solve_puzzle_3(sockfd, ip_addr, port_3, signature);
    if (solved_3 < 0) {
        std::cout << "Failed to solve puzzle 3" << std::endl;
    }

    // Close the socket
    close(sockfd);
    return 0;
}

// Puzzle 3: The dark side of network programming is a pathway to many abilities some consider to be...unnatural. 
// I am an evil port, I will only communicate with evil processes! (https://en.wikipedia.org/wiki/Evil_bit)

// Puzzle 4:  Greetings! I am E.X.P.S.T.N, which stands for "Enhanced X-link Port Storage Transaction Node".
// What can I do for you? 
// If you provide me with a list of secret ports (comma-separated), I can guide you on the exact sequence of "knocks" to ensure you score full marks.

//How to use E.X.P.S.T.N?
// 1. Each "knock" must be paired with both a secret phrase and your unique S.E.C.R.E.T signature.
// 2. The correct format to send a knock: First, 4 bytes containing your S.E.C.R.E.T signature, followed by the secret phrase.

// Tip: To discover the secret ports and their associated phrases, start by solving challenges on the ports detected using your port scanner. Happy hunting!

 
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


const char* SOURCE_ADDRESS = "0.0.0.0";
const uint16_t SOURCE_PORT = 63604;

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
    timeout.tv_sec = 3;
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
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
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
    memset(&server_addr_2, 0, sizeof(sockaddr_in));
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




int solve_puzzle_3(int sockfd, char* dst_ip, uint16_t dst_port, int signature) {
    // Puzzle 3: The dark side of network programming is a pathway to many abilities some consider to be...unnatural. 
    // I am an evil port, I will only communicate with evil processes! (https://en.wikipedia.org/wiki/Evil_bit)

    int IP_HDRINCL_ON = 1;
    int raw_sock;
    //signature = htonl(signature);

    if ((raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
        perror("Unable to create a socket\n");
        return -1;
    }

    if(setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &IP_HDRINCL_ON, sizeof(IP_HDRINCL_ON)) < 0) {
            perror("Unable to set socket options \n");
            close(raw_sock);
    }

    struct sockaddr_in* dst_addr;
    dst_addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
    dst_addr->sin_family = AF_INET;
    dst_addr->sin_port = htons(dst_port);
    dst_addr->sin_addr.s_addr = inet_addr(dst_ip);

    char buffer[1024] = { 0 };
    memset(buffer, 0, sizeof(buffer));

    char* payload = (char*)(buffer + sizeof(struct udphdr) + sizeof(struct ip));
    memcpy(payload, &signature, sizeof(signature));

    udphdr* udp_header = (struct udphdr*)(buffer + sizeof(struct ip));
    udp_header->uh_sport = htons(SOURCE_PORT);
    udp_header->uh_dport = htons(dst_port);
    udp_header->uh_ulen = htons(sizeof(struct udphdr) + sizeof(int));

    char* pseudo_buffer = (char*)calloc((sizeof(struct p_hdr) + sizeof(struct udphdr) + strlen(payload)), sizeof(char));
    if (pseudo_buffer == NULL) {perror("Unable to allocate pseudo buffer\n"); return -1;}

    struct p_hdr pseudo_header;
    pseudo_header.src_addr = inet_addr(SOURCE_ADDRESS);
    pseudo_header.dst_addr = inet_addr(dst_ip);
    pseudo_header.zeros = 0;
    pseudo_header.protocol = IPPROTO_UDP;
    pseudo_header.length = htons(sizeof(struct udphdr) + sizeof(int));

    memcpy(pseudo_buffer, (char*)&pseudo_header, sizeof(struct p_hdr));
    memcpy(pseudo_buffer + sizeof(struct p_hdr), udp_header, sizeof(struct udphdr) + strlen(payload + 1));

    udp_header->uh_sum = calc_checksum(pseudo_buffer, sizeof(struct p_hdr) + sizeof(struct udphdr) + 1);
    free(pseudo_buffer);

    struct ip* ip_header;
    ip_header = (struct ip*)buffer;
    ip_header->ip_hl = 5;
    ip_header->ip_v = 4;
    ip_header->ip_tos = 0;
    ip_header->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + strlen(payload);
    ip_header->ip_ttl = 64;
    ip_header->ip_p = IPPROTO_UDP;
    ip_header->ip_off = (1 << 15);
    struct in_addr source_addr;
    inet_aton(SOURCE_ADDRESS, &source_addr);
    ip_header->ip_src = source_addr;
    struct in_addr destination_addr;
    inet_aton(dst_ip, &destination_addr);
    ip_header->ip_dst = destination_addr;

    ip_header->ip_sum = calc_checksum((char*)ip_header, sizeof(struct ip));
    int sent_bytes;
    if((sent_bytes = sendto(raw_sock, buffer, (sizeof(struct ip) + sizeof(struct udphdr) + strlen(payload)), 0, (struct sockaddr*)dst_addr, sizeof(struct sockaddr_in)))<0) {
        perror("Failed to send raw packet");
    }

    close(raw_sock);

    int new_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (new_sock < 0) {
        perror("Failed to create socket");
        return 1;
    }

    int optval = 1;
    if (setsockopt(new_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        perror("Failed to set SO_REUSEADDR");
        close(new_sock);
        exit(1);
    }


    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = inet_addr(SOURCE_ADDRESS);
    local_addr.sin_port = htons(SOURCE_PORT); // Make sure SOURCE_PORT is a valid port

    if (bind(new_sock, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        perror("Bind failed");
        close(new_sock);
        return -1;
    }

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(sockfd, &read_fds);

    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    int ready_to_read = select(new_sock + 1, &read_fds, NULL, NULL, &timeout);
    if (ready_to_read < 0) {
        std::cout << "Select failed" << std:: endl;
        close(new_sock);
        return -1;
    }

    struct sockaddr_in recv_addr;
    socklen_t recv_len = sizeof(recv_addr);
    char read_buffer[1024];

    int received_bytes = recvfrom(new_sock, read_buffer, sizeof(read_buffer), 0, (struct sockaddr*)&recv_addr, &recv_len);
    if (received_bytes > 0) {
        std::cout << "Recieved response from port: " << dst_port << " after raw packet. Response: " << std::endl << read_buffer << std::dec << std::endl;
    } else {
        perror("Failed to receive message: Raw Sock");
        close(sockfd);
        return -1;
    }
    close(new_sock);
    return 1;
}

char* knock(int sockfd, struct sockaddr_in server_addr, char* knock) {
    if (sendto(sockfd, &knock, sizeof(knock), 0 , (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Failed to send knock");
        return "";
    } 
    std::cout << "Knock successful!" << std::endl;

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(sockfd, &read_fds);

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    int ready_to_read = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);
    if (ready_to_read < 0) {
        perror("Failed to select");
        return "";
    }
    if (ready_to_read == 0) {
        perror("Select timeout");
        return "";
    }

    struct sockaddr_in recv_addr;
    socklen_t recv_len = sizeof(recv_addr);

    char recv_buffer[1024];

    int received_bytes = recvfrom(sockfd, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr*)&recv_addr, &recv_len);
    if (received_bytes > 0) {  
        return recv_buffer;
    } else {
        perror("Failed to receive from server.");
        return "";
    }
}

int solve_puzzle_4(int sockfd, char* dst_ip, int dst_port) {
    // Puzzle 4:  Greetings! I am E.X.P.S.T.N, which stands for "Enhanced X-link Port Storage Transaction Node".
    // What can I do for you? 
    // If you provide me with a list of secret ports (comma-separated), I can guide you on the exact sequence of "knocks" to ensure you score full marks.

    //How to use E.X.P.S.T.N?
    // 1. Each "knock" must be paired with both a secret phrase and your unique S.E.C.R.E.T signature.
    // 2. The correct format to send a knock: First, 4 bytes containing your S.E.C.R.E.T signature, followed by the secret phrase.

    // Tip: To discover the secret ports and their associated phrases, start by solving challenges on the ports detected using your port scanner. Happy hunting!
 
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(dst_port);

    if (inet_pton(AF_INET, dst_ip, &server_addr.sin_addr) <= 0) {
        perror("Invalid address");
        return -1;
    }

    // Construct secret port list
    std::string buffer = "4025,4094";


    if (sendto(sockfd, &buffer, buffer.length(), 0 , (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Failed to send port list");
        return -1;
    } 
    std::cout << "Send successful!" << std::endl;

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(sockfd, &read_fds);

    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;


    int ready_to_read = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);
    if (ready_to_read < 0) {
        perror("Failed to select");
        return -1;
    }
    if (ready_to_read == 0) {
        perror("Select timeout");
        return -1;
    }
    std::cout << "Select successful!" << std::endl;

    struct sockaddr_in recv_addr;
    socklen_t recv_len = sizeof(recv_addr);

    char recv_buffer[1024];

    int received_bytes = recvfrom(sockfd, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr*)&recv_addr, &recv_len);
    if (received_bytes > 0) {  
        std::cout << "Port: " << dst_port << ". Message received: " << recv_buffer << std::endl;
    } else {
        std::cerr << "Failed to receive from server." << std::endl;
        return -1;
    }
}

int port_knocker(int sockfd, char* dst_ip) {
    std::string secret_phrase = "Omae wa mou shindeiru";
    int signature = 0x3293dd49;

    // Create knock
    size_t knock_size = sizeof(signature) + secret_phrase.size();
    char* knock = new char[knock_size];
    memcpy(knock, &signature, sizeof(signature));
    memcpy(knock + sizeof(signature), secret_phrase.c_str(), secret_phrase.size());

    // Construct addresses for the 2 secret ports
    struct sockaddr_in secret_addr_1;
    memset(&secret_addr_1, 0, sizeof(secret_addr_1));
    secret_addr_1.sin_family = AF_INET;
    secret_addr_1.sin_port = htons(4025);

    struct sockaddr_in secret_addr_2;
    memset(&secret_addr_2, 0, sizeof(secret_addr_2));
    secret_addr_2.sin_family = AF_INET;
    secret_addr_2.sin_port = htons(4094);

    // Create list for knocking sequence
    sockaddr_in port_sequence[] =   {secret_addr_1, secret_addr_2, secret_addr_1, 
                                    secret_addr_1, secret_addr_2, secret_addr_2};

    for (int i = 0; i <= 6; i++) {
        char* response = knock_on_port(sockfd, port_sequence[i], knock);
        std::cout << "Response after knock: " << i << "\nRespnse: " << response << std::endl;
    }

    

    free(knock);
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
        perror("Failed to create socket");
        return 1;
    }

    int optval = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        perror("Failed to set SO_REUSEADDR");
        close(sockfd);
        exit(1);
    }


    // Solve puzzle 1:
    int solved_1 = solve_puzzle_1(sockfd, ip_addr, port_1);
    if (solved_1 < 0) {
        std::cout << "Failed to solve puzzle 1" << std::endl;
    }
    // Puzzle solved port: 4045, signiture 3293dd49
    int secret_port = 4045;
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
    // Port 4094
    int evil_port = 4094;


    int solved_4 = solve_puzzle_4(sockfd, ip_addr, port_4);
    if (solved_4 < 0) {
        std::cout << "Failed to solve puzzle 4" << std::endl;
    } 
    close(sockfd);
    return 0;
}

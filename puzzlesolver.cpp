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

// Create a IPv4/pseudo header for the UDP packet since it wont import
struct pseudo_header {
    uint32_t src_ip;
    uint32_t dest_ip;
    uint8_t zero; // All zeroes
    uint8_t protocol; // 4
    uint16_t udp_length; // The length of the UDP header and data (measured in octets(BYTES???))
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




// Function to calculate the current checksum of a package and return the payload
// which changes the checksum to the provided one.
uint16_t calc_payload(char* packet, uint16_t v_checksum, size_t ip_packet_size) {
    uint32_t sum = 0;// 32 bits so overflow can be monitored
    // Note that the size of the packet should be a multiple of 16
    for (size_t i = 0; i < (ip_packet_size-2); i += 2) { // last 2 bytes are payload, we dont check that.
        // Skip the checksum field at the 18th and 19th byte
        if (i == 18) {continue;}
        // Convert the 2 first bytes into a 16 bit variable
        uint16_t bits = (static_cast<uint8_t>(packet[i]) << 8); 
        bits |= static_cast<uint8_t>(packet[i + 1]); 

        sum += bits; // Add the bits to the sum

        // Check for overflow shifting by checking if any bit is set above the 16th bit
        if (sum >> 16) {
            // Create mask to negate all values above 16 and add one
            sum = (sum & 0xFFFF) + 1;
        }
    }
    
    sum = static_cast<uint16_t>(sum);
    std::cout << sum << std::hex << std::endl;
    uint16_t payload = ~(v_checksum) - sum;
    return payload;
}

// Creates a udp packet with a given source and destination IP address, destination port and a checksum
// A valid payload should then be added to this packet so that the checksum is valid 
char* create_packet(uint32_t src_ip, char* dst_ip, uint16_t v_checksum, int dst_port) {
    const int ip_packet_size = sizeof(struct pseudo_header) + sizeof(struct udphdr) + sizeof(uint16_t); // 16 bits for payload
    char* packet = new char[ip_packet_size];

    // Create pseudo header at start of packet
    struct pseudo_header* ipv4_header = (struct pseudo_header*)packet;
    ipv4_header->src_ip = ntohl(src_ip);
    ipv4_header->dest_ip = inet_addr(dst_ip);
    ipv4_header->zero = 0;
    ipv4_header->protocol = IPPROTO_UDP;
    // The udp length would be 16 bits payload + udp header (64 bits), in bytes that is 2 + 8 = 10 bytes
    ipv4_header->udp_length = htons(10); 

    // Create udp header in packet right after pseudo header
    struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct pseudo_header));
    udp_header->uh_sport = htons(1234); // source port
    udp_header->uh_dport = htons(dst_port);
    udp_header->uh_ulen = htons(10);
    udp_header->uh_sum = htons(v_checksum);

    // Payload located at the end of the packet
    uint16_t* payload = (uint16_t*)(packet + sizeof(struct pseudo_header) + sizeof(struct udphdr));
    *payload = 0;  // Placeholder, will be calculated

    // Calculate checksum with initial payload
    uint16_t calculated_payload = calc_payload(packet, v_checksum, ip_packet_size);

    if (calculated_payload == NULL) {
        std::cerr << "Error calculating payload to match checksum." << std::endl;
        return NULL;
    }

    // Insert calculated payload to match the checksum
    *payload = htons(calculated_payload);

    return packet;
}


int solve_puzzle_2(int sockfd, char* ip_addr, int port_2, int sig) {
    struct sockaddr_in server_addr_2;
    memset(&server_addr_2, 0, sizeof(server_addr_2));
    server_addr_2.sin_family = AF_INET;
    server_addr_2.sin_port = htons(port_2);

    // Check if IP is valid
    if (inet_pton(AF_INET, ip_addr, &server_addr_2.sin_addr) <= 0) {
        std::cerr << "Invalid IP address provided." << std::endl;
        return -1;
    }


    if (sendto(sockfd, &sig, 4, 0, (struct sockaddr*)&server_addr_2, sizeof(server_addr_2)) < 0) {
        std::cerr << "Failed to send signature to server." << std::endl;
        close(sockfd);
        return -1;
    }

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
        char buffer[1024];

        int received_bytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&recv_addr, &recv_len);
        if (received_bytes > 0) {
            std::cout << "Message from port: " << port_2 << ", recieved: " << buffer << std::endl;
            // After inspection of the output it can be seen that the last 4 bytes are the source ip address
            // The two bytes before them are the checksum in network byte order
        }
        else {
            std::cerr << "Failed to receive response from server port:" << port_2 << std::endl;
            return -1;
        }
        // Message from port: ff3, recieved: Hello group 47! To get the secret phrase, 
        // reply to this message with a UDP message where the payload is a encapsulated, 
        // valid UDP IPv4 packet, that has a valid UDP checksum of 0xc0d4, and with the source address being 32.132.11.186! 
        // (Hint: all you need is a normal UDP socket which you use to send the IPv4 and UDP headers possibly with a payload) 
        // (the last 6 bytes of this message contain this information in network order)

        // Create variables for checksum and ip read from the last 6 bytes of the buffer
        // IP is 4 bytes long
        uint32_t src_ip;
        // checksum 2 bytes long
        uint16_t v_checksum;

        // Use memcpy to select right bytes for ip and checksum then use ntoh for correct order
        memcpy(&v_checksum, buffer + received_bytes - 6, 2);
        v_checksum = ntohs(v_checksum);
        memcpy(&src_ip, buffer + received_bytes-4, 4);
        src_ip = ntohl(src_ip);


        std::cout << "Source IP: " << src_ip << std::hex << std::endl;
        std::cout << "Checksum: " << v_checksum << std::hex << std::endl;

        // Next step is to calculate what the payload needs to be so that the checksum is equal to v_checksum
        // Lets first create the packet with a empty payload of 16 bits
        // 16 bits should be enough to change the checksum to what we want

        // Create packet with source ip and checksum provided in message
        char* packet = create_packet(src_ip, ip_addr, v_checksum, port_2);
        // Note, source port is just something, as it is not specified.
        if (packet == NULL) {return -1;}



        // Send the packet and wait for response:
        if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr*)&server_addr_2, sizeof(server_addr_2)) < 0) {
            std::cerr << "Failed to send UDP packet to server." << std::endl;
            close(sockfd);
            return -1;
        }
        // Reset timeout and fd_set for select
        FD_ZERO(&read_fds);
        FD_SET(sockfd, &read_fds);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        // Set ready to read to 0 before using select again:
        ready_to_read = 0;
        ready_to_read = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);
        if (ready_to_read > 0) {
            struct sockaddr_in recv_addr;
            memset(buffer, 0, sizeof(buffer));
            int received_bytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&recv_addr, &recv_len);
        if (received_bytes > 0) {
            std::cout << "Response from server after UDP packet was sent to port: " << port_2 << ", Response: " << buffer << std::endl;
            }
        }       
    return -1;
    }
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


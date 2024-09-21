#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <iostream>
#include <unistd.h>
#include <cstdint>  // for uint8_t


int main(int argc, char *argv[]) {
    // Check argument count
    if (argc != 6) {
        std::cout << "Incorrect number of arguments: Should be 5." << std::endl;
        exit(1);
    }
    char* ip_addr = argv[1];
    // Port 1 to 4 should solve be used solve puzzles 1 to 4 respectively
    int port_1, port_2, port_3, port_4;

    // Convert ports 1-4 to integers
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
    int sockfd; 
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        std::cout << "Failed to create socket." << std::endl;
        exit(1);
    }

    // Puzzles to solve in order:

    // Puzzle 1: Greetings from S.E.C.R.E.T (Secure Encryption Certification Relay with Enhanced Trust)! Here's how to access the secret port I'm safeguarding:
    // 1. Send me your group number as a single unsigned byte.
    // 2. I'll reply with a 4-byte challenge (in network byte order) unique to your group.
    // 3. Sign this challenge using the XOR operation with your group's secret (get that from your TA).
    // 4. Reply with a 5-byte message: the first byte is your group number, followed by the 4-byte signed challenge (in network byte order).
    // 5. If your signature is correct, I'll grant you access to the port. Good luck!

    // Create a server address with port 1
    struct sockaddr_in server_addr_1;
    memset(&server_addr_1, 0, sizeof(server_addr_1));
    server_addr_1.sin_family = AF_INET;
    server_addr_1.sin_port = htons(port_1); // htons for network byte order

    // Check if IP is valid 
    if (inet_pton(AF_INET, ip_addr, &server_addr_1.sin_addr) < 1) {
        std::cout << "IP address given is invalid, for port: " << port_1 << std::endl;
        exit(1);
    }
    
    // Create single unsigned message containing group number to send to server at port 1
    std::uint8_t message = 47;
    ssize_t send_msg = sendto(sockfd, &message, 1, 0, (struct sockaddr *)&server_addr_1, sizeof(server_addr_1));
    if (send_msg < 0) {
        std::cout << "Failed to send message, for port 1:" << port_1 << std::endl;
        exit(1);
    }

    fd_set read_fds;
    FD_SET(sockfd, &read_fds);

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    int ready_to_read = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);
    if (ready_to_read > 0) {
        struct sockaddr_in recv_addr;
        socklen_t recv_len = sizeof(recv_addr);
        std::uint32_t challenge;
        int recv_msg = recvfrom(sockfd, &challenge, 4, 0, (struct sockaddr*)&recv_addr, &recv_len);

        if (recv_msg > 0) {
            std::cout << "Port: " << port_1 << ", is open. Response: " << std::hex << challenge << std::endl;
        }
        else {
            std::cout << "Failed to recieve" << std::endl;
        }
    }

// Puzzle 2: Send me a 4-byte message containing the signature you got from S.E.C.R.E.T in the first 4 bytes (in network byte order).

// Puzzle 3: The dark side of network programming is a pathway to many abilities some consider to be...unnatural. 
// I am an evil port, I will only communicate with evil processes! (https://en.wikipedia.org/wiki/Evil_bit)

// Puzzle 4:  Greetings! I am E.X.P.S.T.N, which stands for "Enhanced X-link Port Storage Transaction Node".
// What can I do for you? 
// If you provide me with a list of secret ports (comma-separated), I can guide you on the exact sequence of "knocks" to ensure you score full marks.

//How to use E.X.P.S.T.N?
// 1. Each "knock" must be paired with both a secret phrase and your unique S.E.C.R.E.T signature.
// 2. The correct format to send a knock: First, 4 bytes containing your S.E.C.R.E.T signature, followed by the secret phrase.

// Tip: To discover the secret ports and their associated phrases, start by solving challenges on the ports detected using your port scanner. Happy hunting!


}
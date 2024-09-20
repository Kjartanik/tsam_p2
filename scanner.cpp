#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <iostream>
#include <unistd.h>

char[] isOpen(int sockfd, const char* ip_addr, int port) {
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port)
    // Check if IP is valid 
    if (inet_pton(AF_INET, ip_string, &server_addr.sin_addr) < 1) {
        std::cout << "IP address given is invalid, for port: " << port << std::endl;
        return NULL;
    }

    const char* message = "Knock Knock.";
    struct timaval timeout;
    ssize_t send_msg = sendto(sockfd, message, strlen(message), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (send_msg < 0) {
        std::cout << "Failed to send message, for port:" << port << std::endl;
        return NULL;
    }

    fd
}

int main(int argc, char *argv[]) {
    // Check argument count
    if (argc != 4) {
        std::cout << "Incorrect number of arguments: Should be 3." << std::endl;
    }
    char* ip_addr = argv[1];
    int low_port, high_port;

    try {
        int low_port = std::stoi(argv[2]);
        int high_port = std::stoi(argv[3]);
    }
    catch (std::invalid_argument& e) {
        std::cout << "Both ports must be a number." << std::endl;
        exit(1);
    } 
    catch (std::out_of_range& e) {
        std::cout << "Both ports must be a number between 0 and 65535." << std::endl;
        exit(1);
    }
    if (port < 1 || port > 65535) {
        std::cout << "Both ports must be a number between 0 and 65535" << std::endl;
        exit(1);
    }

    // Create socket
    int sockfd 
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Failed to create socket.")
        exit(1);
    }

    for (int port = low_port; port <= high_port; port++) {
        n = isOpen(sockfd, server_addr, port);

    }

    
}
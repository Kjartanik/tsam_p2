#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <iostream>
#include <unistd.h>

char[] isOpen(int sockfd, const char* ip_addr, int port) {
    
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
        if isOpen(sockfd, ip_addr, port)
    }

    
}
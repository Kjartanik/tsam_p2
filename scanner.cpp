#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <iostream>
#include <unistd.h>

bool isOpen(int sockfd, const char* ip_addr, int port) {

    // Create server address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port); // htons for network byte order

    // Check if IP is valid 
    if (inet_pton(AF_INET, ip_addr, &server_addr.sin_addr) < 1) {
        std::cout << "IP address given is invalid, for port: " << port << std::endl;
        return false;
    }

    // Create message to send and response to return
    const char* message = "Knock Knock.";
    const char* response;
    ssize_t send_msg = sendto(sockfd, message, strlen(message), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (send_msg < 0) {
        std::cout << "Failed to send message, for port:" << port << std::endl;
        return false;
    }

    // Create file descriptor set for select
    fd_set read_fds;
    FD_SET(sockfd, &read_fds);
    
    // Create timeout for select
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    int n = select(sockfd + 1, &read_fds, NULL, NULL, &timeout); // select socket to see if it's ready to read

    // If socket ready, read from it
    if (n > 0 && FD_ISSET(sockfd, &read_fds)) {
        // Create socket address to ww
        struct sockaddr_in recv_addr;
        socklen_t recv_len = sizeof(recv_addr);
        char buffer[1024];
        memset(buffer, 0, sizeof(buffer));
        int recv_msg = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&recv_addr, &recv_len);

        if (recv_msg > 0) {
            std::cout << "Port: " << port << ", is open. Response: " << buffer << std::endl;
            return true;
        }
    }
    return false;

}

int main(int argc, char *argv[]) {
    // Check argument count
    if (argc != 4) {
        std::cout << "Incorrect number of arguments: Should be 3." << std::endl;
    }
    char* ip_addr = argv[1];
    int low_port, high_port;

    try {
        low_port = std::stoi(argv[2]);
        high_port = std::stoi(argv[3]);
    }
    catch (std::invalid_argument& e) {
        std::cout << "Both ports must be a number." << std::endl;
        exit(1);
    } 
    catch (std::out_of_range& e) {
        std::cout << "Both ports must be a number between 0 and 65535." << std::endl;
        exit(1);
    }
    if (low_port < 1 || low_port > 65535 || high_port < 1 || high_port > 65535) {
        std::cout << "Both ports must be a number between 0 and 65535" << std::endl;
        exit(1);
    }

    // Create socket
    int sockfd; 
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Failed to create socket.");
        exit(1);
    }

    for (int port = low_port; port <= high_port; port++) {
        bool n;
        n = isOpen(sockfd, ip_addr, port);
    }

    close(sockfd);
    return 0;
}
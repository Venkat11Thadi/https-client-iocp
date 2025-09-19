#include <winsock2.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <chrono>

#include <openssl/ssl.h>
#include <openssl/err.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mswsock.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

// ==> EDIT THESE VALUES <==
#define SERVER_HOST "cdn.thingiverse.com"
#define SERVER_PORT 443

// Operation types for our custom OVERLAPPED structure
enum class IO_OPERATION {
    // Note: CLIENT_CONNECT is no longer used with WSAConnect, but kept for reference
    CLIENT_CONNECT,
    SSL_HANDSHAKE,
    SSL_READ,
    SSL_WRITE
};

// Custom OVERLAPPED structure to hold per-operation data
struct PER_IO_DATA {
    OVERLAPPED overlapped;
    IO_OPERATION operation;
    WSABUF wsaBuf;
    char buffer[8192];
};

// Per-socket data structure
struct PER_SOCKET_DATA {
    SOCKET socket;
    SSL* ssl;
    // Store the start time for performance measurement
    std::chrono::steady_clock::time_point request_start_time;
};

// Global handles
HANDLE g_iocpHandle = NULL;
HANDLE g_hQuitEvent = NULL;

// Function Prototypes
DWORD WINAPI WorkerThread(LPVOID lpParam);
void StartSslHandshake(PER_SOCKET_DATA* pSocketData, PER_IO_DATA* pIoData);
void PostSslRead(PER_SOCKET_DATA* pSocketData, PER_IO_DATA* pIoData);

int main() {
    // 1. Initialize Winsock & OpenSSL
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed." << std::endl;
        return 1;
    }

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "SSL_CTX_new failed." << std::endl;
        return 1;
    }

    g_hQuitEvent = CreateEvent(NULL, TRUE, FALSE, NULL); // Manual-reset, initially non-signaled

    // 2. Create IOCP & Worker Threads
    g_iocpHandle = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (g_iocpHandle == NULL) {
        std::cerr << "CreateIoCompletionPort failed." << std::endl;
        return 1;
    }
    CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);

    // 3. Resolve Server Address
    addrinfo hints = {}, * servinfo = nullptr;
    hints.ai_family = AF_INET; // Force IPv4
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(SERVER_HOST, std::to_string(SERVER_PORT).c_str(), &hints, &servinfo) != 0) {
        std::cerr << "getaddrinfo failed for host: " << SERVER_HOST << std::endl;
        return 1;
    }

    // 4. Create Socket
    SOCKET clientSocket = WSASocket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "WSASocket failed: " << WSAGetLastError() << std::endl;
        freeaddrinfo(servinfo);
        return 1;
    }

    // 5. Connect using WSAConnect (BLOCKING)
    std::cout << "Attempting to connect to " << SERVER_HOST << "..." << std::endl;
    if (WSAConnect(clientSocket, servinfo->ai_addr, (int)servinfo->ai_addrlen, NULL, NULL, NULL, NULL) == SOCKET_ERROR) {
        std::cerr << "WSAConnect failed: " << WSAGetLastError() << std::endl;
        closesocket(clientSocket);
        freeaddrinfo(servinfo);
        return 1;
    }
    std::cout << "Connection established." << std::endl;
    freeaddrinfo(servinfo);

    // 6. Associate the NOW-CONNECTED Socket with IOCP
    PER_SOCKET_DATA* pSocketData = new PER_SOCKET_DATA();
    pSocketData->socket = clientSocket;
    if (CreateIoCompletionPort((HANDLE)clientSocket, g_iocpHandle, (ULONG_PTR)pSocketData, 0) == NULL) {
        std::cerr << "Failed to associate socket with IOCP." << std::endl;
        return 1;
    }

    // 7. Create SSL object and set SNI
    pSocketData->ssl = SSL_new(ctx);
    SSL_set_fd(pSocketData->ssl, (int)clientSocket);
    SSL_set_tlsext_host_name(pSocketData->ssl, SERVER_HOST);

    // 8. Start the timer and post the first job to the IOCP to begin the SSL handshake
    pSocketData->request_start_time = std::chrono::steady_clock::now();

    PER_IO_DATA* pIoData = new PER_IO_DATA();
    ZeroMemory(pIoData, sizeof(PER_IO_DATA));
    pIoData->operation = IO_OPERATION::SSL_HANDSHAKE;

    PostQueuedCompletionStatus(g_iocpHandle, 0, (ULONG_PTR)pSocketData, (LPOVERLAPPED)pIoData);

    std::cout << "\n--- Waiting for request to complete... ---\n" << std::endl;
    WaitForSingleObject(g_hQuitEvent, INFINITE); // Wait forever until signaled
    std::cout << "\n--- Request complete. Exiting. ---\n" << std::endl;

    // Cleanup
    closesocket(clientSocket);
    SSL_CTX_free(ctx);
    WSACleanup();
    return 0;
}

DWORD WINAPI WorkerThread(LPVOID lpParam) {
    DWORD bytesTransferred;
    PER_SOCKET_DATA* pSocketData = nullptr;
    PER_IO_DATA* pIoData = nullptr;

    while (true) {
        BOOL result = GetQueuedCompletionStatus(g_iocpHandle, &bytesTransferred,
            (PULONG_PTR)&pSocketData,
            (LPOVERLAPPED*)&pIoData, INFINITE);

        // --- CORRECTED LOGIC ---
        // Only treat a 0-byte I/O on a READ operation as a disconnect.
        if (result && bytesTransferred == 0 && pIoData->operation == IO_OPERATION::SSL_READ) {

            // (The timing and cout logic is unchanged)
            auto end_time = std::chrono::steady_clock::now();

            auto duration = end_time - pSocketData->request_start_time;
            double elapsed_ms = std::chrono::duration<double, std::milli>(duration).count();
            // ...
            std::cout << "Total round-trip time: " << elapsed_ms << " ms" << std::endl;
            std::cout << "----------------------------------------" << std::endl;

            // (Cleanup logic is unchanged)
            closesocket(pSocketData->socket);
            // ...
            delete pIoData;

            // ==> SIGNAL THE MAIN THREAD TO QUIT <==
            SetEvent(g_hQuitEvent);

            continue; // Continue the loop to wait for other potential work
        }

        if (!result) {
            std::cout << "no result" << std::endl;
            continue;
        }

        switch (pIoData->operation) {
        case IO_OPERATION::SSL_HANDSHAKE: {
            StartSslHandshake(pSocketData, pIoData);
            break;
        }
        case IO_OPERATION::SSL_READ: {
            PostSslRead(pSocketData, pIoData);
            break;
        }
        }
    }
    return 0;
}

void StartSslHandshake(PER_SOCKET_DATA* pSocketData, PER_IO_DATA* pIoData) {
    int ret = SSL_connect(pSocketData->ssl);
    int err = SSL_get_error(pSocketData->ssl, ret);

    if (ret == 1) {
        std::cout << "SSL Handshake successful!" << std::endl;

        const char* request_path = "/assets/d9/db/40/b9/1e/ezgif-1d0c06ef205ac1.webp";
        std::string request = "GET " + std::string(request_path) + " HTTP/1.1\r\n" +
            "Host: " + std::string(SERVER_HOST) + "\r\n" +
            "Connection: close\r\n\r\n";

        SSL_write(pSocketData->ssl, request.c_str(), (int)request.length());

        // Handshake and write are done, now start reading the response
        PostSslRead(pSocketData, pIoData);
    }
    else if (err == SSL_ERROR_WANT_READ) {
        pIoData->operation = IO_OPERATION::SSL_HANDSHAKE;
        pIoData->wsaBuf.buf = pIoData->buffer;
        pIoData->wsaBuf.len = sizeof(pIoData->buffer);
        DWORD flags = 0;
        ZeroMemory(&pIoData->overlapped, sizeof(OVERLAPPED));
        WSARecv(pSocketData->socket, &pIoData->wsaBuf, 1, NULL, &flags, &pIoData->overlapped, NULL);
    }
    else {
        std::cerr << "SSL Handshake failed. Error: " << err << std::endl;
        ERR_print_errors_fp(stderr);
    }
}

void PostSslRead(PER_SOCKET_DATA* pSocketData, PER_IO_DATA* pIoData) {
    char read_buffer[4096];

    // Loop to process any data OpenSSL has already buffered internally
    while (true) {
        int bytesRead = SSL_read(pSocketData->ssl, read_buffer, sizeof(read_buffer) - 1);

        if (bytesRead > 0) {
            read_buffer[bytesRead] = '\0';
            std::cout << read_buffer;
        }
        else {
            int err = SSL_get_error(pSocketData->ssl, bytesRead);
            if (err == SSL_ERROR_WANT_READ) {
                // OpenSSL needs more data from the network. Post an async read.
                pIoData->operation = IO_OPERATION::SSL_READ;
                pIoData->wsaBuf.buf = pIoData->buffer;
                pIoData->wsaBuf.len = sizeof(pIoData->buffer);
                DWORD flags = 0;
                ZeroMemory(&pIoData->overlapped, sizeof(OVERLAPPED));
                WSARecv(pSocketData->socket, &pIoData->wsaBuf, 1, NULL, &flags, &pIoData->overlapped, NULL);
                // Break the loop; we are now waiting for the async operation to complete.
                break;
            }
            else {
                // SSL_ERROR_ZERO_RETURN or another error occurred.
                auto end_time = std::chrono::steady_clock::now();

                auto duration = end_time - pSocketData->request_start_time;
                double elapsed_ms = std::chrono::duration<double, std::milli>(duration).count();

                std::cout << "Total round-trip time: " << elapsed_ms/1000 << " sec" << std::endl;
                std::cout << "----------------------------------------" << std::endl;

                // (Cleanup logic is unchanged)
                closesocket(pSocketData->socket);
                // ...
                delete pIoData;

                // ==> SIGNAL THE MAIN THREAD TO QUIT <==
                SetEvent(g_hQuitEvent);
                break;
            }
        }
    }
}
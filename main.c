#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

#define PORT "8080"
#define DEFAULT_BUFLEN 8192

const char *get_mime_type(const char *path) {
  if (strstr(path, ".html"))
    return "text/html";
  if (strstr(path, ".js") || strstr(path, ".mjs"))
    return "application/javascript";
  if (strstr(path, ".css"))
    return "text/css";
  if (strstr(path, ".svg"))
    return "image/svg+xml";
  if (strstr(path, ".wasm"))
    return "application/wasm";
  if (strstr(path, ".png"))
    return "image/png";
  if (strstr(path, ".jpg") || strstr(path, ".jpeg"))
    return "image/jpeg";
  if (strstr(path, ".json"))
    return "application/json";
  if (strstr(path, ".ico"))
    return "image/x-icon";
  if (strstr(path, ".otf") || strstr(path, ".ttf") || strstr(path, ".woff") ||
      strstr(path, ".woff2"))
    return "font/opentype";
  return "application/octet-stream";
}

int send_all(SOCKET s, const char *buf, long long len) {
  long long total_sent = 0;
  while (total_sent < len) {
    int to_send = (len - total_sent > 16384) ? 16384 : (int)(len - total_sent);
    int sent = send(s, buf + total_sent, to_send, 0);
    if (sent == SOCKET_ERROR)
      return -1;
    total_sent += sent;
  }
  return 0;
}

void handle_client(SOCKET client_socket) {
  char recvbuf[DEFAULT_BUFLEN];
  int iResult = recv(client_socket, recvbuf, DEFAULT_BUFLEN - 1, 0);

  if (iResult > 0) {
    recvbuf[iResult] = '\0';
    char method[10], path[512], protocol[20];
    if (sscanf(recvbuf, "%s %s %s", method, path, protocol) < 2) {
      printf("Failed to parse request: %s\n", recvbuf);
      closesocket(client_socket);
      return;
    }
    printf("Request: %s %s\n", method, path);

    // Ignore query string
    char *query = strchr(path, '?');
    if (query)
      *query = '\0';

    if (strcmp(method, "GET") == 0) {
      char actual_path[1024] = "build/web";
      if (strcmp(path, "/") == 0) {
        strcat(actual_path, "/index.html");
      } else {
        strcat(actual_path, path);
      }

      // Convert to backslashes if needed (WinAPI fopen handles both, but let's
      // be safe)
      for (int i = 0; actual_path[i]; i++)
        if (actual_path[i] == '/')
          actual_path[i] = '\\';

      FILE *f = fopen(actual_path, "rb");
      // If file not found, try serving index.html (for SPA routing)
      if (!f && !strchr(path, '.')) {
        strcpy(actual_path, "build\\web\\index.html");
        f = fopen(actual_path, "rb");
      }

      if (f) {
        _fseeki64(f, 0, SEEK_END);
        long long fsize = _ftelli64(f);
        _fseeki64(f, 0, SEEK_SET);

        char header[1024];
        sprintf(header,
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: %s\r\n"
                "Content-Length: %lld\r\n"
                "Cache-Control: public, max-age=3600\r\n"
                "X-Content-Type-Options: nosniff\r\n"
                "Connection: close\r\n\r\n",
                get_mime_type(actual_path), fsize);
        send(client_socket, header, (int)strlen(header), 0);

        char *buffer = malloc((size_t)fsize);
        if (buffer) {
          fread(buffer, 1, (size_t)fsize, f);
          if (send_all(client_socket, buffer, fsize) == -1) {
            printf("Send failed for: %s\n", actual_path);
          }
          free(buffer);
          printf("200 OK: %s (%lld bytes)\n", actual_path, fsize);
          if (strstr(actual_path, "index.html")) {
            printf(">> The application may take a few moments to load. Please "
                   "wait... / 애플리케이션 로딩에 시간이 걸릴 수 있습니다. "
                   "잠시만 기다려 주세요...\n");
          }
        }
        fclose(f);
      } else {
        const char *not_found = "HTTP/1.1 404 Not Found\r\n"
                                "Content-Type: text/plain\r\n"
                                "Content-Length: 9\r\n"
                                "Connection: close\r\n\r\n"
                                "Not Found";
        send(client_socket, not_found, (int)strlen(not_found), 0);
        printf("404 Not Found: %s\n", actual_path);
      }
    }
  }
  closesocket(client_socket);
}

int main() {
  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    return 1;

  struct addrinfo *result = NULL, hints;
  ZeroMemory(&hints, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE;

  if (getaddrinfo(NULL, PORT, &hints, &result) != 0) {
    WSACleanup();
    return 1;
  }

  SOCKET listen_socket =
      socket(result->ai_family, result->ai_socktype, result->ai_protocol);
  if (listen_socket == INVALID_SOCKET) {
    freeaddrinfo(result);
    WSACleanup();
    return 1;
  }

  if (bind(listen_socket, result->ai_addr, (int)result->ai_addrlen) ==
      SOCKET_ERROR) {
    freeaddrinfo(result);
    closesocket(listen_socket);
    WSACleanup();
    return 1;
  }

  freeaddrinfo(result);

  if (listen(listen_socket, SOMAXCONN) == SOCKET_ERROR) {
    closesocket(listen_socket);
    WSACleanup();
    return 1;
  }

  printf("Server listening at http://localhost:%s\n", PORT);
  while (1) {
    SOCKET client_socket = accept(listen_socket, NULL, NULL);
    if (client_socket != INVALID_SOCKET)
      handle_client(client_socket);
  }

  closesocket(listen_socket);
  WSACleanup();
  return 0;
}

#define _CRT_SECURE_NO_WARNINGS
#include "header/io.h"
#include "header/stdio.h"
#include "header/stdlib.h"
#include "header/string.h"
#include "header/winsock2.h"
#include "header/ws2tcpip.h"
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "secur32.lib")

#define SECURITY_WIN32
#include <schannel.h>
#include <security.h>

#define PORT "8080"
#define HTTPS_PORT "8443"
#define DEFAULT_BUFLEN 8192

typedef struct {
  CredHandle hCreds;
  CtxtHandle hContext;
  BOOL bInitialized;
  SecPkgContext_StreamSizes StreamSizes;
} SSLContext;

// Function stubs for HTTPS/SChannel
int init_schannel(SSLContext *ctx);
void cleanup_schannel(SSLContext *ctx);
int handle_https_handshake(SOCKET s, SSLContext *ctx);
int ssl_send(SOCKET s, SSLContext *ctx, const char *buf, int len);
int ssl_recv(SOCKET s, SSLContext *ctx, char *buf, int len);

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

void handle_client(SOCKET client_socket, SSLContext *ctx, BOOL is_https) {
  char recvbuf[DEFAULT_BUFLEN];
  int iResult;

  if (is_https) {
    if (handle_https_handshake(client_socket, ctx) != 0) {
      closesocket(client_socket);
      return;
    }
    iResult = ssl_recv(client_socket, ctx, recvbuf, DEFAULT_BUFLEN - 1);
  } else {
    iResult = recv(client_socket, recvbuf, DEFAULT_BUFLEN - 1, 0);
  }

  if (iResult > 0) {
    recvbuf[iResult] = '\0';
    char method[10], path[512], protocol[20];
    if (sscanf(recvbuf, "%s %s %s", method, path, protocol) < 2) {
      printf("Failed to parse request: %s\n", recvbuf);
      closesocket(client_socket);
      return;
    }
    printf("Request (%s): %s %s\n", is_https ? "HTTPS" : "HTTP", method, path);

    // Ignore query string
    char *query = strchr(path, '?');
    if (query)
      *query = '\0';

    if (strcmp(method, "GET") == 0) {
      // Basic directory traversal protection
      if (strstr(path, "..")) {
        const char *forbidden = "HTTP/1.1 403 Forbidden\r\n"
                                "Content-Type: text/plain\r\n"
                                "Content-Length: 9\r\n"
                                "Connection: close\r\n\r\n"
                                "Forbidden";
        if (is_https)
          ssl_send(client_socket, ctx, forbidden, (int)strlen(forbidden));
        else
          send(client_socket, forbidden, (int)strlen(forbidden), 0);

        printf("403 Forbidden: %s (Traversal attempt)\n", path);
        closesocket(client_socket);
        return;
      }

      char actual_path[1024];
      // Try serving from "www" folder first, fallback to root
      if (_access("www", 0) == 0) {
        strcpy(actual_path, "www");
      } else {
        strcpy(actual_path, ".");
      }

      if (strcmp(path, "/") == 0) {
        strcat(actual_path, "/index.html");
      } else {
        strcat(actual_path, path);
      }

      // Convert to backslashes for Windows
      for (int i = 0; actual_path[i]; i++)
        if (actual_path[i] == '/')
          actual_path[i] = '\\';

      FILE *f = fopen(actual_path, "rb");

      // If file not found, check if it's a SPA-style route (no dot in path)
      if (!f && !strchr(path, '.')) {
        if (strstr(actual_path, "www\\")) {
          strcpy(actual_path, "www\\index.html");
        } else {
          strcpy(actual_path, ".\\index.html");
        }
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

        if (is_https)
          ssl_send(client_socket, ctx, header, (int)strlen(header));
        else
          send(client_socket, header, (int)strlen(header), 0);

        char *buffer = malloc((size_t)fsize);
        if (buffer) {
          fread(buffer, 1, (size_t)fsize, f);
          if (is_https)
            ssl_send(client_socket, ctx, buffer, (int)fsize);
          else
            send_all(client_socket, buffer, fsize);
          free(buffer);
          printf("200 OK: %s (%lld bytes)\n", actual_path, fsize);
        }
        fclose(f);
      } else {
        const char *not_found = "HTTP/1.1 404 Not Found\r\n"
                                "Content-Type: text/plain\r\n"
                                "Content-Length: 9\r\n"
                                "Connection: close\r\n\r\n"
                                "Not Found";
        if (is_https)
          ssl_send(client_socket, ctx, not_found, (int)strlen(not_found));
        else
          send(client_socket, not_found, (int)strlen(not_found), 0);
        printf("404 Not Found: %s\n", actual_path);
      }
    }
  }
  closesocket(client_socket);
}

// HTTPS/SChannel Implementation
int init_schannel(SSLContext *ctx) {
  SCHANNEL_CRED schannelCred = {0};
  schannelCred.dwVersion = SCHANNEL_CRED_VERSION;
  schannelCred.grbitEnabledProtocols =
      SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER;
  schannelCred.dwFlags =
      SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_AUTO_CRED_VALIDATION;

  SECURITY_STATUS status =
      AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_INBOUND, NULL,
                                &schannelCred, NULL, NULL, &ctx->hCreds, NULL);

  if (status != SEC_E_OK) {
    printf("AcquireCredentialsHandle failed: 0x%08X\n", (unsigned int)status);
    return -1;
  }
  ctx->bInitialized = TRUE;
  return 0;
}

void cleanup_schannel(SSLContext *ctx) {
  if (ctx->bInitialized) {
    FreeCredentialsHandle(&ctx->hCreds);
    DeleteSecurityContext(&ctx->hContext);
    ctx->bInitialized = FALSE;
  }
}

int handle_https_handshake(SOCKET s, SSLContext *ctx) {
  SecBufferDesc outBufferDesc, inBufferDesc;
  SecBuffer outBuffers[1], inBuffers[2];
  char inBuf[DEFAULT_BUFLEN], outBuf[DEFAULT_BUFLEN];
  DWORD flags = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT |
                ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR |
                ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM;
  DWORD outFlags;
  TimeStamp expiry;
  SECURITY_STATUS status = SEC_I_CONTINUE_NEEDED;
  BOOL bFirst = TRUE;

  while (status == SEC_I_CONTINUE_NEEDED ||
         status == SEC_E_INCOMPLETE_MESSAGE ||
         status == SEC_I_INCOMPLETE_CREDENTIALS) {
    int bytes_received = recv(s, inBuf, sizeof(inBuf), 0);
    if (bytes_received <= 0)
      return -1;

    inBuffers[0].pvBuffer = inBuf;
    inBuffers[0].cbBuffer = bytes_received;
    inBuffers[0].BufferType = SECBUFFER_TOKEN;
    inBuffers[1].pvBuffer = NULL;
    inBuffers[1].cbBuffer = 0;
    inBuffers[1].BufferType = SECBUFFER_EMPTY;

    inBufferDesc.cBuffers = 2;
    inBufferDesc.pBuffers = inBuffers;
    inBufferDesc.ulVersion = SECBUFFER_VERSION;

    outBuffers[0].pvBuffer = NULL;
    outBuffers[0].cbBuffer = 0;
    outBuffers[0].BufferType = SECBUFFER_TOKEN;
    outBufferDesc.cBuffers = 1;
    outBufferDesc.pBuffers = outBuffers;
    outBufferDesc.ulVersion = SECBUFFER_VERSION;

    status = AcceptSecurityContext(&ctx->hCreds, bFirst ? NULL : &ctx->hContext,
                                   &inBufferDesc, flags, SECURITY_NATIVE_DREP,
                                   &ctx->hContext, &outBufferDesc, &outFlags,
                                   &expiry);

    if (status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED) {
      if (outBuffers[0].cbBuffer > 0 && outBuffers[0].pvBuffer != NULL) {
        send(s, outBuffers[0].pvBuffer, outBuffers[0].cbBuffer, 0);
        FreeContextBuffer(outBuffers[0].pvBuffer);
      }
    }
    bFirst = FALSE;
    if (status == SEC_E_OK)
      break;
    if (FAILED(status) && status != SEC_E_INCOMPLETE_MESSAGE) {
      printf("AcceptSecurityContext failed: 0x%08X\n", (unsigned int)status);
      return -1;
    }
  }

  QueryContextAttributesA(&ctx->hContext, SECPKG_ATTR_STREAM_SIZES,
                          &ctx->StreamSizes);
  return 0;
}

int ssl_send(SOCKET s, SSLContext *ctx, const char *buf, int len) {
  SecBufferDesc BuffDesc;
  SecBuffer Buffs[4];
  char *pMsg =
      malloc(ctx->StreamSizes.cbHeader + len + ctx->StreamSizes.cbTrailer);
  if (!pMsg)
    return -1;

  memcpy(pMsg + ctx->StreamSizes.cbHeader, buf, len);

  Buffs[0].pvBuffer = pMsg;
  Buffs[0].cbBuffer = ctx->StreamSizes.cbHeader;
  Buffs[0].BufferType = SECBUFFER_STREAM_HEADER;

  Buffs[1].pvBuffer = pMsg + ctx->StreamSizes.cbHeader;
  Buffs[1].cbBuffer = len;
  Buffs[1].BufferType = SECBUFFER_DATA;

  Buffs[2].pvBuffer = pMsg + ctx->StreamSizes.cbHeader + len;
  Buffs[2].cbBuffer = ctx->StreamSizes.cbTrailer;
  Buffs[2].BufferType = SECBUFFER_STREAM_TRAILER;

  Buffs[3].pvBuffer = NULL;
  Buffs[3].cbBuffer = 0;
  Buffs[3].BufferType = SECBUFFER_EMPTY;

  BuffDesc.ulVersion = SECBUFFER_VERSION;
  BuffDesc.cBuffers = 4;
  BuffDesc.pBuffers = Buffs;

  SECURITY_STATUS status = EncryptMessage(&ctx->hContext, 0, &BuffDesc, 0);
  if (status != SEC_E_OK) {
    free(pMsg);
    return -1;
  }

  int total_to_send = Buffs[0].cbBuffer + Buffs[1].cbBuffer + Buffs[2].cbBuffer;
  int sent = send(s, pMsg, total_to_send, 0);
  free(pMsg);
  return sent;
}

int ssl_recv(SOCKET s, SSLContext *ctx, char *buf, int len) {
  SecBufferDesc BuffDesc;
  SecBuffer Buffs[4];
  char inBuf[DEFAULT_BUFLEN];
  int bytes_received = recv(s, inBuf, sizeof(inBuf), 0);
  if (bytes_received <= 0)
    return bytes_received;

  Buffs[0].pvBuffer = inBuf;
  Buffs[0].cbBuffer = bytes_received;
  Buffs[0].BufferType = SECBUFFER_DATA;
  Buffs[1].BufferType = SECBUFFER_EMPTY;
  Buffs[2].BufferType = SECBUFFER_EMPTY;
  Buffs[3].BufferType = SECBUFFER_EMPTY;

  BuffDesc.ulVersion = SECBUFFER_VERSION;
  BuffDesc.cBuffers = 4;
  BuffDesc.pBuffers = Buffs;

  SECURITY_STATUS status = DecryptMessage(&ctx->hContext, &BuffDesc, 0, NULL);
  if (status != SEC_E_OK && status != SEC_I_RENEGOTIATE)
    return -1;

  // Find the data buffer
  for (int i = 0; i < 4; i++) {
    if (Buffs[i].BufferType == SECBUFFER_DATA) {
      int to_copy =
          (Buffs[i].cbBuffer > (unsigned int)len) ? len : Buffs[i].cbBuffer;
      memcpy(buf, Buffs[i].pvBuffer, to_copy);
      return to_copy;
    }
  }
  return 0;
}

int main() {
  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    return 1;

  SSLContext ssl_ctx = {0};
  init_schannel(&ssl_ctx);

  struct addrinfo *result = NULL, hints;
  ZeroMemory(&hints, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE;

  // Setup HTTP Listener
  getaddrinfo(NULL, PORT, &hints, &result);
  SOCKET http_socket =
      socket(result->ai_family, result->ai_socktype, result->ai_protocol);
  bind(http_socket, result->ai_addr, (int)result->ai_addrlen);
  listen(http_socket, SOMAXCONN);
  freeaddrinfo(result);

  // Setup HTTPS Listener
  getaddrinfo(NULL, HTTPS_PORT, &hints, &result);
  SOCKET https_socket =
      socket(result->ai_family, result->ai_socktype, result->ai_protocol);
  bind(https_socket, result->ai_addr, (int)result->ai_addrlen);
  listen(https_socket, SOMAXCONN);
  freeaddrinfo(result);

  // Setup HTTP/3 (UDP) Placeholder
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  getaddrinfo(NULL, HTTPS_PORT, &hints, &result);
  SOCKET http3_socket =
      socket(result->ai_family, result->ai_socktype, result->ai_protocol);
  bind(http3_socket, result->ai_addr, (int)result->ai_addrlen);
  freeaddrinfo(result);

  printf("Server listening:\n");
  printf("  HTTP:  http://localhost:%s\n", PORT);
  printf("  HTTPS: https://localhost:%s\n", HTTPS_PORT);
  printf("  HTTP/3: udp://localhost:%s (Placeholder)\n", HTTPS_PORT);

  fd_set readfds;
  while (1) {
    FD_ZERO(&readfds);
    FD_SET(http_socket, &readfds);
    FD_SET(https_socket, &readfds);
    FD_SET(http3_socket, &readfds);

    if (select(0, &readfds, NULL, NULL, NULL) > 0) {
      if (FD_ISSET(http_socket, &readfds)) {
        SOCKET client = accept(http_socket, NULL, NULL);
        if (client != INVALID_SOCKET)
          handle_client(client, &ssl_ctx, FALSE);
      }
      if (FD_ISSET(https_socket, &readfds)) {
        SOCKET client = accept(https_socket, NULL, NULL);
        if (client != INVALID_SOCKET)
          handle_client(client, &ssl_ctx, TRUE);
      }
      if (FD_ISSET(http3_socket, &readfds)) {
        char buf[DEFAULT_BUFLEN];
        struct sockaddr_in client_addr;
        int addr_len = sizeof(client_addr);
        int len = recvfrom(http3_socket, buf, sizeof(buf), 0,
                           (struct sockaddr *)&client_addr, &addr_len);
        if (len > 0) {
          printf("HTTP/3 (UDP) packet received (%d bytes)\n", len);
          // In a real implementation, we would pass this to a QUIC state
          // machine. For now, we just acknowledge receipt.
        }
      }
    }
  }

  cleanup_schannel(&ssl_ctx);
  closesocket(http_socket);
  closesocket(https_socket);
  closesocket(http3_socket);
  WSACleanup();
  return 0;
}

#include <winsock2.h>
#include <ws2tcpip.h> 
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")

#include <stdio.h>
#include <stdlib.h>

#include <time.h>
#include <stdint.h>
#pragma warning( disable : 4996 )

using namespace std;
#define SERVER_PORT 8554
#define SERVER_RTP_PORT 55532
#define SERVER_RTCP_PORT 55533

// �������
#define ERROR_EXIT(msg) { fprintf(stderr, "%s: %d\n", msg, WSAGetLastError()); exit(EXIT_FAILURE); }

// RTPͷ�ṹ
typedef struct {
	uint8_t version;
	uint8_t payload;
	uint8_t seq[2];
	uint8_t timestamp[4];
	uint8_t ssrc[4];
} RTPHeader;

// ����RTP�׽���
static int createRtpSocket(const char* ip, int port) {
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == INVALID_SOCKET) {
		return -1;
	}

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(ip);

	if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
		closesocket(sockfd);
		return -1;
	}

	return sockfd;
}

// ����TCP�׽���
static int createTcpSocket()
{
	int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sockfd == INVALID_SOCKET)
		ERROR_EXIT("Socket creation failed");

	// ���õ�ַ����
	int on = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on)) == SOCKET_ERROR)
	{
		closesocket(sockfd);
		ERROR_EXIT("Setsockopt failed")
	}

	return sockfd;
}

// ���׽��ֵ�ַ
static int bindSocketAddr(int sockfd, const char* ip, int port)
{
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.S_un.S_addr = (ip == NULL) ? INADDR_ANY : inet_addr(ip);// ��� ip Ϊ NULL����󶨵����п��õ� IP ��ַ��INADDR_ANY�������򣬰󶨵�ָ���� IP ��ַ��

	if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR)
	{
		closesocket(sockfd);
		ERROR_EXIT("Bind failed");
	}

	return 0;
}

// ���տͻ�������
static int acceptClient(int sockfd, char* ip, int* port)
{
	struct sockaddr_in addr;
	int addrLen = sizeof(addr);

	int clientfd = accept(sockfd, (struct sockaddr*)&addr, &addrLen);
	if (clientfd == INVALID_SOCKET)
	{
		ERROR_EXIT("accept failed");
	}

	strcpy(ip, inet_ntoa(addr.sin_addr));
	*port = ntohs(addr.sin_port);

	return clientfd;
}

// ����OPTIONS����
static void handleCmd_OPTIONS(int clientSockfd, int cseq) {
	char response[256];
	snprintf(response, sizeof(response),
		"RTSP/1.0 200 OK\r\n"
		"CSeq: %d\r\n"
		"Public: OPTIONS, DESCRIBE, SETUP, PLAY\r\n"
		"\r\n",
		cseq);
	send(clientSockfd, response, strlen(response), 0);
}
// ����DESCRIBE����
static void handleCmd_DESCRIBE(int clientSockfd, int cseq, const char* url)
{
	char sdp[512];
	char response[1024];
	char ip[100];

	// ��URL����ȡIP
	sscanf(url, "rtsp://%[^:]", ip);

	// ����SDP����
	snprintf(sdp, sizeof(sdp),
		"v=0\r\n"
		"o=- %ld 1 IN IP4 %s\r\n"
		"s=My Video Stream\r\n"
		"i=This is a test video stream.\r\n"
		"t=0 0\r\n"
		"a=control:*\r\n"
		"c=IN IP4 %s\r\n"
		"m=video %d RTP/AVP 96\r\n"
		"a=rtpmap:96 H264/90000\r\n"
		"a=control:track0\r\n"
		"m=audio %d RTP/AVP 0\r\n"
		"a=rtpmap:0 PCMU/8000\r\n"
		"a=control:track1\r\n",
		time(NULL), ip, ip, SERVER_RTP_PORT, SERVER_RTP_PORT + 2);

	// ������Ӧ
	snprintf(response, sizeof(response),
		"RTSP/1.0 200 OK\r\n"
		"CSeq: %d\r\n"
		"Content-Base: %s\r\n"
		"Content-Type: application/sdp\r\n"
		"Content-Length: %zu\r\n"
		"\r\n"
		"%s",
		cseq, url, strlen(sdp), sdp);

	send(clientSockfd, response, strlen(response), 0);
}
// ����SETUP����
static void handleCmd_SETUP(int clientSockfd, int cseq, int clientRtpPort)
{
	char response[256];
	snprintf(response, sizeof(response),
		"RTSP/1.0 200 OK\r\n"
		"CSeq: %d\r\n"
		"Transport: RTP/AVP;unicast;client_port=%d-%d;server_port=%d-%d\r\n"
		"Session: 66334873\r\n"
		"\r\n",
		cseq,
		clientRtpPort,
		clientRtpPort + 1,
		SERVER_RTP_PORT,
		SERVER_RTCP_PORT);

	send(clientSockfd, response, strlen(response), 0);
}
// ����PLAY����
static void handleCmd_PLAY(int clientSockfd, int cseq) {
	char response[256];
	snprintf(response, sizeof(response),
		"RTSP/1.0 200 OK\r\n"
		"CSeq: %d\r\n"
		"Range: npt=0.000-\r\n"
		"Session: 66334873; timeout=10\r\n"
		"\r\n",
		cseq);

	send(clientSockfd, response, strlen(response), 0);
}

static void sendTestRtpPackets(const char* clientIP, int clientRtpPort);
// �ͻ��˴��������
static void handleClient(int clientSockfd, const char* clientIP, int clientPort) {
	printf("New client connected: %s:%d\n", clientIP, clientPort);

	char buffer[2048];
	int recvLen;
	int cseq = 0;
	int clientRtpPort = 0;

	while ((recvLen = recv(clientSockfd, buffer, sizeof(buffer) - 1, 0) > 0)) {
		buffer[recvLen] = '\0';
		printf("Received request:\n%s\n", buffer);

		// ��������
		char method[32] = { 0 };
		char url[256] = { 0 };
		char version[32] = { 0 };
		int newCseq = 0;
		int newClientRtpPort = 0;

		// ���н���
		char* line = strtok(buffer, "\r\n");
		while (line) {
			if (sscanf(line, "%s %s %s", method, url, version) == 3) {
				// ����������
			}
			else if (strstr(line, "CSeq:")) {
				sscanf(line, "CSeq: %d", &newCseq);
			}
			else if (strstr(line, "Transport:")) {
				char* portStr = strstr(line, "client_port=");
				if (portStr) {
					sscanf(portStr + 12, "%d", &newClientRtpPort);
				}
			}
			line = strtok(NULL, "\r\n");
		}

		if (newCseq > 0) cseq = newCseq;
		if (newClientRtpPort > 0) clientRtpPort = newClientRtpPort;

		// ��������
		if (strcmp(method, "OPTIONS") == 0) {
			handleCmd_OPTIONS(clientSockfd, cseq);
		}
		else if (strcmp(method, "DESCRIBE") == 0) {
			handleCmd_DESCRIBE(clientSockfd, cseq, url);
		}
		else if (strcmp(method, "SETUP") == 0) {
			handleCmd_SETUP(clientSockfd, cseq, clientRtpPort);
		}
		else if (strcmp(method, "PLAY") == 0) {
			handleCmd_PLAY(clientSockfd, cseq);
			printf("Start streaming to %s:%d\n", clientIP, clientRtpPort);
			// ����Ӧ�ÿ�ʼRTP������
			if (strcmp(method, "PLAY") == 0) {
				handleCmd_PLAY(clientSockfd, cseq);
				printf("Start streaming to %s:%d\n", clientIP, clientRtpPort);
				sendTestRtpPackets(clientIP, clientRtpPort);
			}
		}
		else {
			printf("Unknown method: %s\n", method);
			break;
		}
	}

	closesocket(clientSockfd);
	printf("Client disconnected: %s:%d\n", clientIP, clientPort);
}

// ���Ͳ���RTP��
static void sendTestRtpPackets(const char* clientIP, int clientRtpPort) {
	int rtpSock = createRtpSocket("0.0.0.0", SERVER_RTP_PORT);
	if (rtpSock == -1) {
		printf("Failed to create RTP socket\n");
		return;
	}

	struct sockaddr_in clientAddr;
	clientAddr.sin_family = AF_INET;
	clientAddr.sin_port = htons(clientRtpPort);
	clientAddr.sin_addr.s_addr = inet_addr(clientIP);

	RTPHeader header;
	header.version = 0x80;  // RTP�汾
	header.payload = 96;    // H264��������

	uint16_t seq = 0;
	uint32_t timestamp = 0;

	// ����һЩ���԰�
	for (int i = 0; i < 100; i++) {
		// ���ͷ
		header.seq[0] = (seq >> 8) & 0xFF;
		header.seq[1] = seq & 0xFF;

		header.timestamp[0] = (timestamp >> 24) & 0xFF;
		header.timestamp[1] = (timestamp >> 16) & 0xFF;
		header.timestamp[2] = (timestamp >> 8) & 0xFF;
		header.timestamp[3] = timestamp & 0xFF;

		// �򵥵Ĳ��Ը���
		char payload[] = "Test RTP packet";

		// ��ϰ�
		char packet[sizeof(RTPHeader) + sizeof(payload)];
		memcpy(packet, &header, sizeof(RTPHeader));
		memcpy(packet + sizeof(RTPHeader), payload, sizeof(payload));

		// ����
		sendto(rtpSock, packet, sizeof(packet), 0,
			(struct sockaddr*)&clientAddr, sizeof(clientAddr));

		seq++;
		timestamp += 3600;  // ����30fps��90000/30=3000

		Sleep(33);  // Լ30fps
	}

	closesocket(rtpSock);
}

int main(int argc, char* argv[])
{
	// ��ʼ��Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		ERROR_EXIT("WSAStartup failed");
		return -1;
	}

	printf("RTSP Server starting...\n");

	// �����������׽���
	int serverSockfd = createTcpSocket();

	// �����нӿڵ�8554�˿�
	if (bindSocketAddr(serverSockfd, NULL, SERVER_PORT) < 0)
	{
		closesocket(serverSockfd);
		ERROR_EXIT("Bind failed");
	}

	// ��ʼ����
	if (listen(serverSockfd, 10) == SOCKET_ERROR)
	{
		closesocket(serverSockfd);
		ERROR_EXIT("Listen failed");
	}

	printf("%s rtsp://127.0.0.1:%d\n", __FILE__, SERVER_PORT);


	// ���տͻ��˲�����
	while (1) {
		char clientIP[16];
		int clientPort;

		printf("Waiting for client connection...\n");
		int clientSockfd = acceptClient(serverSockfd, clientIP, &clientPort);

		handleClient(clientSockfd, clientIP, clientPort);
	}

	closesocket(serverSockfd);
	WSACleanup();
	return 0;
}
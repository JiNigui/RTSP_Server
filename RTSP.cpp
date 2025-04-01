#include <winsock2.h>
#include <ws2tcpip.h> 
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")

#include <stdio.h>
#include <stdlib.h>

#include <time.h>
#include <stdint.h>
#pragma warning( disable : 4996 )
#include "RTP.h"

using namespace std;
#define SERVER_PORT 8554
#define SERVER_RTP_PORT 55532
#define SERVER_RTCP_PORT 55533
#define BUF_MAX_SIZE     (1024*1024)
#define H264_FILE_NAME "C:\\Users\\71472\\Desktop\\V_test\\cat.h264"

// 错误处理宏
#define ERROR_EXIT(msg) { fprintf(stderr, "%s: %d\n", msg, WSAGetLastError()); exit(EXIT_FAILURE); }

// 创建TCP套接字
static int createTcpSocket()
{
	int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sockfd == INVALID_SOCKET)
		ERROR_EXIT("Socket creation failed");

	// 设置地址重用
	int on = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on)) == SOCKET_ERROR)
	{
		closesocket(sockfd);
		ERROR_EXIT("Setsockopt failed")
	}

	return sockfd;
}
static int createUdpSocket()
{
	int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sockfd == INVALID_SOCKET)
		ERROR_EXIT("Socket creation failed");

	// 设置地址重用
	int on = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on)) == SOCKET_ERROR)
	{
		closesocket(sockfd);
		ERROR_EXIT("Setsockopt failed")
	}

	return sockfd;
}


// 绑定套接字地址ַ
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

// 接收客户端连接
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

// 处理OPTIONS命令
static int handleCmd_OPTIONS(int clientSockfd, int cseq) {
	char response[256];
	snprintf(response, sizeof(response),
		"RTSP/1.0 200 OK\r\n"
		"CSeq: %d\r\n"
		"Public: OPTIONS, DESCRIBE, SETUP, PLAY\r\n"
		"\r\n",
		cseq);
	send(clientSockfd, response, strlen(response), 0);

	return 0;
}
// 处理DESCRIBE命令
static int handleCmd_DESCRIBE(int clientSockfd, int cseq, const char* url)
{
	char sdp[512];
	char response[1024];
	char ip[100];

	// 从URL中提取IP
	sscanf(url, "rtsp://%[^:]", ip);

	// 生成SDP描述
	snprintf(sdp, sizeof(sdp),
		"v=0\r\n"
		"o=- %ld 1 IN IP4 %s\r\n"
		"t=0 0\r\n"
		"a=control:*\r\n"
		"m=video %d RTP/AVP 96\r\n"
		"a=rtpmap:96 H264/90000\r\n"
		"a=control:track0\r\n",
		time(NULL), ip, SERVER_RTP_PORT);

	// 生成响应
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

	return 0;
}
// 处理SETUP命令
static int handleCmd_SETUP(int clientSockfd, int cseq, int clientRtpPort)
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

	return 0;
}
// 处理PLAY命令
static int handleCmd_PLAY(int clientSockfd, int cseq) {
	char response[256];
	snprintf(response, sizeof(response),
		"RTSP/1.0 200 OK\r\n"
		"CSeq: %d\r\n"
		"Range: npt=0.000-\r\n"
		"Session: 66334873; timeout=10\r\n"
		"\r\n",
		cseq);

	send(clientSockfd, response, strlen(response), 0);

	return 0;
}

int rtpSendH264Packets(int serverRtpSockfd, const char* clientIP, int clientRtpPort);
// 客户端处理函数框架
static void handleClient(int clientSockfd, const char* clientIP, int clientPort) {
	printf("New client connected: %s:%d\n", clientIP, clientPort);

	char buffer[4096];
	int recvLen;
	int cseq = 0;
	int clientRtpPort = 0, clientRtcpPort = 0;
	int serverRtpSockfd = -1, serverRtcpSockfd = -1;

	while (true) {
		// 接收RTSP请求
		recvLen = recv(clientSockfd, buffer, sizeof(buffer) - 1, 0);
		if (recvLen <= 0) {
			printf("Client disconnected or error\n");
			break;
		}
		buffer[recvLen] = '\0';
		printf("Raw request:\n%.*s\n", recvLen, buffer);

		// 解析请求
		char method[32] = { 0 };
		char url[256] = { 0 };
		char version[32] = { 0 };
		int newCseq = 0;
		int newClientRtpPort = 0, newClientRtcpPort = 0;

		// 逐行解析
		char* line = strtok(buffer, "\n");
		while (line) {
			char* cr_pos = strchr(line, '\r');
			if (cr_pos != NULL) *cr_pos = '\0';

			if (strncmp(line, "OPTIONS", 7) == 0 ||
				strncmp(line, "DESCRIBE", 8) == 0 ||
				strncmp(line, "SETUP", 5) == 0 ||
				strncmp(line, "PLAY", 4) == 0) {
				sscanf(line, "%31s %255s %31s \n", method, url, version);
				// 这是请求行
			}
			else if (strstr(line, "CSeq:")) {
				if (sscanf(line, "CSeq: %d \n", &newCseq) != 1) {
					printf("Failed to parse CSeq\n");
				}
			}
			else if (strstr(line, "Transport:")) {
				char* portStr = strstr(line, "client_port=");
				if (portStr) {
					if (sscanf(portStr + 12, "%d-%d", &newClientRtpPort, &newClientRtcpPort) != 2) {
						printf("Failed to parse client ports\n");
					}
				}
			}
			line = strtok(NULL, "\n");
		}

		if (newCseq > 0) cseq = newCseq;
		if (newClientRtpPort > 0) clientRtpPort = newClientRtpPort;
		if (newClientRtcpPort > 0) clientRtcpPort = newClientRtcpPort;

		// 处理命令
		if (strcmp(method, "OPTIONS") == 0) {
			if (handleCmd_OPTIONS(clientSockfd, cseq)) {
				printf("OPTIONS handling failed\n");
				break;
			}
		}
		else if (strcmp(method, "DESCRIBE") == 0) {
			if (handleCmd_DESCRIBE(clientSockfd, cseq, url)) {
				printf("DESCRIBE handling failed\n");
				break;
			}
		}
		else if (strcmp(method, "SETUP") == 0) {
			if (handleCmd_SETUP(clientSockfd, cseq, clientRtpPort)) {
				printf("SETUP handling failed\n");
				break;
			}

			// 创建并绑定RTP/RTCP套接字
			if (serverRtpSockfd < 0) {
				serverRtpSockfd = createUdpSocket();
				serverRtcpSockfd = createUdpSocket();
				if (serverRtpSockfd < 0 || serverRtcpSockfd < 0) {
					printf("Failed to create UDP sockets\n");
					break;
				}
			}

			if (bindSocketAddr(serverRtpSockfd, "0.0.0.0", SERVER_RTP_PORT) < 0 ||
				bindSocketAddr(serverRtcpSockfd, "0.0.0.0", SERVER_RTCP_PORT) < 0) {
				printf("Failed to bind UDP sockets\n");
				break;
			}
		}
		else if (strcmp(method, "PLAY") == 0) {
			if (handleCmd_PLAY(clientSockfd, cseq)) {
				printf("PLAY handling failed\n");
				break;
			}
			printf("Start streaming to %s:%d\n", clientIP, clientRtpPort);
			if (!rtpSendH264Packets(serverRtpSockfd, clientIP, clientRtpPort))
				printf("Succeeded to send H264");
			else
				printf("Failed to send H264");
		}
		else {
			printf("Unknown method: %s\n", method);
			break;
		}
	}

	// 清理资源
	if (serverRtpSockfd >= 0) closesocket(serverRtpSockfd);
	if (serverRtcpSockfd >= 0) closesocket(serverRtcpSockfd);
	closesocket(clientSockfd);
	printf("Client disconnected: %s:%d\n", clientIP, clientPort);
}

// H.264起始码检测函数
static inline int startCode3(char* buf) {
	return (buf[0] == 0 && buf[1] == 0 && buf[2] == 1);
}

static inline int startCode4(char* buf) {
	return (buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] == 1);
}

static char* findNextStartCode(char* buf, int len) {
	if (len < 3) return NULL;

	for (int i = 0; i < len - 3; ++i) {
		if (startCode3(buf) || startCode4(buf))
			return buf;
		++buf;
	}

	return startCode3(buf) ? buf : NULL;
}

static int getFrameFromH264File(FILE* fp, char* frame, int size);
static int rtpSendH264Frame(int serverRtpSockfd, const char* ip, int16_t port,
	struct RtpPacket* rtpPacket, char* frame, uint32_t frameSize);
// 发送H264文件
int rtpSendH264Packets(int serverRtpSockfd, const char* clientIP, int clientRtpPort) {// 1. 初始化变量和分配内存
	int frameSize, startCode;
	char* frame = (char*)malloc(500000);// 不一定够
	struct RtpPacket* rtpPacket = (struct RtpPacket*)malloc(500000);

	if (!frame || !rtpPacket) {
		printf("内存分配失败\n");
		if (frame) free(frame);
		if (rtpPacket) free(rtpPacket);
		return -1;
	}

	// 打开H264文件
	FILE* fp = fopen(H264_FILE_NAME, "rb");
	if (!fp) {
		printf("读取 %s 失败\n", H264_FILE_NAME);
		free(frame);
		free(rtpPacket);
		return -1;
	}

	// 初始化RTP包头
	rtpHeaderInit(rtpPacket, 0, 0, 0, RTP_VERSION, RTP_PAYLOAD_TYPE_H264,
		0, 0, 0, 0x88923423);

	printf("开始播放视频流\n");
	printf("客户端地址: %s:%d\n", clientIP, clientRtpPort);

	// 主发送循环
	while (true) {
		frameSize = getFrameFromH264File(fp, frame, 500000);
		if (frameSize < 0) {
			printf("视频文件读取结束\n");
			break;
		}

		// 检测起始码(0x00 00 01 或 0x00 00 00 01)
		startCode = startCode3(frame) ? 3 : 4;
		frameSize -= startCode;

		// 发送RTP包h264
		rtpSendH264Frame(serverRtpSockfd, clientIP, clientRtpPort,
			rtpPacket, frame + startCode, frameSize);

		// 控制帧率(约25fps)
		Sleep(40); // Windows
	}

	// 清理资源
	fclose(fp);
	free(frame);
	free(rtpPacket);

	return 0;
}

// 从H.264视频文件中提取单个完整的NALU
static int getFrameFromH264File(FILE* fp, char* frame, int size)
{
	if (!fp || !frame || size <= 0) return -1;

	int rSize = fread(frame, 1, size, fp);
	if (rSize <= 0) return -1;  // 文件结束或读取错误

	// 检查当前缓冲区起始位置是否有合法的起始码
	if (!startCode3(frame) && !startCode4(frame)) {
		return -1;  // 无效的起始码
	}

	// 查找下一个起始码位置
	char* nextStart = findNextStartCode(frame + 3, rSize - 3);
	if (!nextStart) {
		// 没有找到下一个起始码，可能是文件末尾的最后一帧
		return rSize;  // 返回当前读取的全部数据作为一帧
	}

	// 计算当前帧的大小（从当前起始码到下一个起始码）
	int frameSize = nextStart - frame;

	// 调整文件指针到下一帧的起始位置
	fseek(fp, frameSize - rSize, SEEK_CUR);

	return frameSize;
}
// 发送H264流
static int rtpSendH264Frame(int serverRtpSockfd, const char* ip, int16_t port,
	struct RtpPacket* rtpPacket, char* frame, uint32_t frameSize)
{
	uint8_t naluType = frame[0]; // NALU类型
	int sendBytes = 0;
	int ret;

	if (frameSize <= RTP_MAX_PKT_SIZE) {
		// 单一NALU单元模式
		memcpy(rtpPacket->payload, frame, frameSize);
		ret = rtpSendPacketOverUdp(serverRtpSockfd, ip, port, rtpPacket, frameSize);
		if (ret < 0) return -1;

		rtpPacket->rtpHeader.seq++;
		sendBytes += ret;

		// SPS/PPS不需要增加时间戳
		if ((naluType & 0x1F) == 7 || (naluType & 0x1F) == 8)
			return sendBytes;
	}
	else {
		// FU-A分片模式
		int pktNum = frameSize / RTP_MAX_PKT_SIZE;
		int remainPktSize = frameSize % RTP_MAX_PKT_SIZE;
		int pos = 1; // 跳过起始码

		for (int i = 0; i < pktNum; i++) {
			rtpPacket->payload[0] = (naluType & 0x60) | 28; // FU indicator
			rtpPacket->payload[1] = naluType & 0x1F;        // FU header

			if (i == 0) // 第一包
				rtpPacket->payload[1] |= 0x80; // Start标记
			else if (remainPktSize == 0 && i == pktNum - 1) // 最后一包
				rtpPacket->payload[1] |= 0x40; // End标记

			memcpy(rtpPacket->payload + 2, frame + pos, RTP_MAX_PKT_SIZE);
			ret = rtpSendPacketOverUdp(serverRtpSockfd, ip, port, rtpPacket, RTP_MAX_PKT_SIZE + 2);
			if (ret < 0) return -1;

			rtpPacket->rtpHeader.seq++;
			sendBytes += ret;
			pos += RTP_MAX_PKT_SIZE;
		}

		// 发送剩余数据
		if (remainPktSize > 0) {
			rtpPacket->payload[0] = (naluType & 0x60) | 28;
			rtpPacket->payload[1] = (naluType & 0x1F) | 0x40; // End标记

			memcpy(rtpPacket->payload + 2, frame + pos, remainPktSize);
			ret = rtpSendPacketOverUdp(serverRtpSockfd, ip, port, rtpPacket, remainPktSize + 2);
			if (ret < 0) return -1;

			rtpPacket->rtpHeader.seq++;
			sendBytes += ret;
		}
	}

	// 增加时间戳 (假设25fps)
	rtpPacket->rtpHeader.timestamp += 90000 / 25;
	return sendBytes;
}
int main(int argc, char* argv[])
{
	// 初始化Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		ERROR_EXIT("WSAStartup failed");
		return -1;
	}

	printf("RTSP Server starting...\n");

	// 创建服务器套接字
	int serverSockfd = createTcpSocket();

	// 绑定所有接口的8554端口
	if (bindSocketAddr(serverSockfd, NULL, SERVER_PORT) < 0)
	{
		closesocket(serverSockfd);
		ERROR_EXIT("Bind failed");
	}

	// 开始监听
	if (listen(serverSockfd, 10) == SOCKET_ERROR)
	{
		closesocket(serverSockfd);
		ERROR_EXIT("Listen failed");
	}

	printf("%s rtsp://127.0.0.1:%d\n", __FILE__, SERVER_PORT);


	// 接收客户端并处理
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
#include <chrono>
#include <thread>
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
#define AAC_FILE_NAME "C:\\Users\\71472\\Desktop\\V_test\\cat.aac"

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
	addr.sin_addr.S_un.S_addr = (ip == NULL) ? INADDR_ANY : inet_addr(ip);//     ip Ϊ NULL    󶨵    п  õ  IP   ַ  INADDR_ANY       򣬰󶨵 ָ     IP   ַ  

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

// 定义aac数据包；h264因为相较来说数据包格式比较简单，直接在函数中进行处理即可
struct AdtsHeader {
	unsigned int syncword;  //12 bit 同步字 '1111 1111 1111'，一个ADTS帧的开始
	uint8_t id;        //1 bit 0代表MPEG-4, 1代表MPEG-2。
	uint8_t layer;     //2 bit 必须为0
	uint8_t protectionAbsent;  //1 bit 1代表没有CRC，0代表有CRC
	uint8_t profile;           //1 bit AAC级别（MPEG-2 AAC中定义了3种profile，MPEG-4 AAC中定义了6种profile）
	uint8_t samplingFreqIndex; //4 bit 采样率
	uint8_t privateBit;        //1bit 编码时设置为0，解码时忽略
	uint8_t channelCfg;        //3 bit 声道数量
	uint8_t originalCopy;      //1bit 编码时设置为0，解码时忽略
	uint8_t home;               //1 bit 编码时设置为0，解码时忽略

	uint8_t copyrightIdentificationBit;   //1 bit 编码时设置为0，解码时忽略
	uint8_t copyrightIdentificationStart; //1 bit 编码时设置为0，解码时忽略
	unsigned int aacFrameLength;               //13 bit 一个ADTS帧的长度包括ADTS头和AAC原始流
	unsigned int adtsBufferFullness;           //11 bit 缓冲区充满度，0x7FF说明是码率可变的码流，不需要此字段。CBR可能需要此字段，不同编码器使用情况不同。这个在使用音频编码的时候需要注意。

	/* number_of_raw_data_blocks_in_frame
	 * 表示ADTS帧中有number_of_raw_data_blocks_in_frame + 1个AAC原始帧
	 * 所以说number_of_raw_data_blocks_in_frame == 0
	 * 表示说ADTS帧中有一个AAC数据块并不是说没有。(一个AAC原始帧包含一段时间内1024个采样及相关数据)
	 */
	uint8_t numberOfRawDataBlockInFrame; //2 bit
};
static int parseAdtsHeader(uint8_t* in, struct AdtsHeader* res) {
	static int frame_number = 0;
	memset(res, 0, sizeof(*res));

	if ((in[0] == 0xFF) && ((in[1] & 0xF0) == 0xF0))
	{
		res->id = ((uint8_t)in[1] & 0x08) >> 3;//第二个字节与0x08与运算之后，获得第13位bit对应的值
		res->layer = ((uint8_t)in[1] & 0x06) >> 1;//第二个字节与0x06与运算之后，右移1位，获得第14,15位两个bit对应的值
		res->protectionAbsent = (uint8_t)in[1] & 0x01;
		res->profile = ((uint8_t)in[2] & 0xc0) >> 6;
		res->samplingFreqIndex = ((uint8_t)in[2] & 0x3c) >> 2;
		res->privateBit = ((uint8_t)in[2] & 0x02) >> 1;
		res->channelCfg = ((((uint8_t)in[2] & 0x01) << 2) | (((unsigned int)in[3] & 0xc0) >> 6));
		res->originalCopy = ((uint8_t)in[3] & 0x20) >> 5;
		res->home = ((uint8_t)in[3] & 0x10) >> 4;
		res->copyrightIdentificationBit = ((uint8_t)in[3] & 0x08) >> 3;
		res->copyrightIdentificationStart = (uint8_t)in[3] & 0x04 >> 2;

		res->aacFrameLength = (((((unsigned int)in[3]) & 0x03) << 11) |
			(((unsigned int)in[4] & 0xFF) << 3) |
			((unsigned int)in[5] & 0xE0) >> 5);

		res->adtsBufferFullness = (((unsigned int)in[5] & 0x1f) << 6 |
			((unsigned int)in[6] & 0xfc) >> 2);
		res->numberOfRawDataBlockInFrame = ((uint8_t)in[6] & 0x03);

		return 0;
	}
	else
	{
		ERROR_EXIT("failed to parse adts header");
		return -1;
	}
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
static int handleCmd_DESCRIBE(int clientSockfd, int cseq, const char* url) {
	char sdp[2048];  // 扩大缓冲区
	char response[4096];
	char ip[100] = { 0 };  // 显式初始化

	// 安全解析URL（限制长度）
	if (sscanf(url, "rtsp://%99[^:/]", ip) != 1) {
		strncpy(ip, "127.0.0.1", sizeof(ip) - 1);
	}

	// 生成SDP（确保字符串拼接正确）
	int sdp_len = snprintf(sdp, sizeof(sdp),
		"v=0\r\n"
		"o=- %ld 1 IN IP4 %s\r\n"
		"t=0 0\r\n"
		"a=control:*\r\n"
		"m=video 0 RTP/AVP/TCP 96\r\n"
		"a=rtpmap:96 H264/90000\r\n"
		"a = fmtp:96 packetization-mode=1;profile-level-id=42001F;sprop-parameter-sets=Z0IAH5WoFAFugQ==, aM48gA==\r\n"
		"a=control:track0\r\n"
		"m=audio 0 RTP/AVP/TCP 97\r\n"
		"a=rtpmap:97 MPEG4-GENERIC/44100/2\r\n"  // 修正为MPEG4-GENERIC
		"a=fmtp:97 profile-level-id=1; mode=AAC-hbr; sizelength=13; indexlength=3; indexdeltalength=3; config=1210;\r\n"
		"a=control:track1\r\n",
		time(NULL), ip);

	if (sdp_len < 0 || sdp_len >= sizeof(sdp)) {
		return -1;  // SDP生成失败
	}

	// 生成响应（确保Content-Length正确）
	int ret = snprintf(response, sizeof(response),
		"RTSP/1.0 200 OK\r\n"
		"CSeq: %d\r\n"
		"Content-Base: %s\r\n"
		"Content-Type: application/sdp\r\n"
		"Content-Length: %d\r\n"  // 使用sdp_len而非strlen(sdp)
		"\r\n"
		"%s",
		cseq, url, sdp_len, sdp);

	if (ret < 0 || ret >= sizeof(response)) {
		return -1;  // 响应生成失败
	}

	// 发送响应（检查返回值）
	if (send(clientSockfd, response, ret, 0) <= 0) {
		return -1;
	}

	return 0;
}
// 处理SETUP命令
static int handleCmd_SETUP(int clientSockfd, int cseq, const char* url) {
	// 1. 防御性编程
	if (!url) {
		printf("[ERROR] NULL URL in SETUP\n");
		return -1;
	}

	// 2. 提取track类型
	const char* track = strrchr(url, '/');
	if (!track) {
		printf("[WARN] No track specified, using default video track\n");
		track = "/track0";
	}

	// 3. 生成Transport头
	const char* transport = NULL;
	if (strcmp(track, "/track0") == 0) {
		transport = "RTP/AVP/TCP;unicast;interleaved=0-1";
	}
	else if (strcmp(track, "/track1") == 0) {
		transport = "RTP/AVP/TCP;unicast;interleaved=2-3";
	}
	else {
		printf("[ERROR] Unsupported track: %s\n", track);
		return -1;
	}

	// 4. 生成响应
	char response[512];
	int ret = snprintf(response, sizeof(response),
		"RTSP/1.0 200 OK\r\n"
		"CSeq: %d\r\n"
		"Transport: %s\r\n"
		"Session: 66334873; timeout=60\r\n"
		"\r\n",
		cseq, transport);

	if (ret < 0 || ret >= sizeof(response)) {
		printf("[ERROR] Response buffer overflow\n");
		return -1;
	}

	// 5. 发送响应
	printf("[SERVER] SETUP Response:\n%s\n", response);
	return send(clientSockfd, response, strlen(response), 0) > 0 ? 0 : -1;
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

static int getFrameFromH264File(FILE* fp, char* frame, int size);
static int rtpSendH264Frame(int clientSockfd, struct RtpPacket* rtpPacket, char* frame, uint32_t frameSize, uint32_t* timestamp);

static int getFrameFromAACFile(FILE* fp, char* frame, int size, struct AdtsHeader* adtsHeader);
static int rtpSendAACFrame(int clientSockfd, struct RtpPacket* rtpPacket, char* frame, uint32_t frameSize, uint32_t* timestamp);

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

// 发送音视频数据
static void sendMediaStream(int clientSockfd) {
	printf("开始播放音视频流\n");

	// 视频发送线程
	thread videoThread([clientSockfd]() {
		FILE* video_fp = fopen(H264_FILE_NAME, "rb");
		if (!video_fp) {
			printf("读取 %s 失败\n", H264_FILE_NAME);
			return;
		}

		struct RtpPacket* rtpPacket = (struct RtpPacket*)malloc(500000);
		char* video_frame = (char*)malloc(500000);
		if (!rtpPacket || !video_frame) {
			fclose(video_fp);
			free(rtpPacket);
			free(video_frame);
			return;
		}

		rtpHeaderInit(rtpPacket, 0, 0, 0, RTP_VERSION, RTP_PAYLOAD_TYPE_H264,
			0, 0, 0, 0x88923423);

		uint32_t video_timestamp = 0;
		const int h264_frame_interval = 40; // 25fps = 40ms

		while (true) {
			int frameSize = getFrameFromH264File(video_fp, video_frame, 500000);
			if (frameSize < 0) {
				printf("视频文件读取结束\n");
				break;
			}

			int startCode = startCode3(video_frame) ? 3 : 4;
			uint8_t naluType = video_frame[startCode] & 0x1F;

			rtpPacket->rtpHeader.timestamp = video_timestamp;
			rtpSendH264Frame(clientSockfd, rtpPacket,
				video_frame + startCode,
				frameSize - startCode,
				&video_timestamp);

			video_timestamp += 3600; // 90000/2

			std::this_thread::sleep_for(std::chrono::milliseconds(h264_frame_interval));
		}

		fclose(video_fp);
		free(rtpPacket);
		free(video_frame);
		});

	// 音频发送线程
	thread audioThread([clientSockfd]() {
		FILE* audio_fp = fopen(AAC_FILE_NAME, "rb");
		if (!audio_fp) {
			printf("读取 %s 失败\n", AAC_FILE_NAME);
			return;
		}

		struct RtpPacket* rtpPacket = (struct RtpPacket*)malloc(5000);
		char* audio_frame = (char*)malloc(5000);
		struct AdtsHeader adtsHeader;
		if (!rtpPacket || !audio_frame) {
			fclose(audio_fp);
			free(rtpPacket);
			free(audio_frame);
			return;
		}

		rtpHeaderInit(rtpPacket, 0, 0, 0, RTP_VERSION, RTP_PAYLOAD_TYPE_AAC,
			1, 0, 0, 0x32411);

		uint32_t audio_timestamp = 0;
		const int aac_frame_duration = 23; // AAC帧间隔(约43fps);改成15，可流畅播放aac，去除无效视频帧，但不同步
		

		while (true) {
			int frameSize = getFrameFromAACFile(audio_fp, audio_frame, 5000, &adtsHeader);
			if (frameSize < 0) {
				printf("音频文件读取结束\n");
				break;
			}

			rtpPacket->rtpHeader.timestamp = audio_timestamp;
			rtpSendAACFrame(clientSockfd, rtpPacket,
				audio_frame, frameSize,
				&audio_timestamp);
			/*
             * 如果采样频率是44100
             * 一般AAC每个1024个采样为一帧
             * 所以一秒就有 44100 / 1024 = 43帧
             * 时间增量就是 44100 / 43 = 1025
             * 一帧的时间为 1 / 43 = 23ms
             */

			audio_timestamp += 1025; // 同步到视频时钟
			std::this_thread::sleep_for(std::chrono::milliseconds(aac_frame_duration));
		}

		fclose(audio_fp);
		free(rtpPacket);
		free(audio_frame);
		});

	// 等待线程结束
	videoThread.join();
	audioThread.join();
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

// 发送H264帧
static int rtpSendH264Frame(int clientSockfd, struct RtpPacket* rtpPacket,
	char* frame, uint32_t frameSize, uint32_t* timestamp)
{
	uint8_t naluType = frame[0]; // NALU类型
	int sendBytes = 0;
	int ret;

	// 设置RTP头
	rtpPacket->rtpHeader.timestamp = *timestamp;

	if (frameSize <= RTP_MAX_PKT_SIZE) {
		// 单一NALU单元模式
		memcpy(rtpPacket->payload, frame, frameSize);
		ret = rtpSendPacketOverTcp(clientSockfd, rtpPacket, frameSize, 0x00);
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
			ret = rtpSendPacketOverTcp(clientSockfd, rtpPacket, RTP_MAX_PKT_SIZE + 2, 0x00);
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
			ret = rtpSendPacketOverTcp(clientSockfd, rtpPacket, remainPktSize + 2, 0x00);
			if (ret < 0) return -1;

			rtpPacket->rtpHeader.seq++;
			sendBytes += ret;
		}
	}

	return sendBytes;
}

// 从AAC文件中提取帧
static int getFrameFromAACFile(FILE* fp, char* frame, int size, struct AdtsHeader* adtsHeader)
{
	if (!fp || !frame || size <= 0) return -1;

	// 读取ADTS头
	if (fread(frame, 1, 7, fp) != 7) {
		return -1;
	}

	// 解析ADTS头
	if (parseAdtsHeader((uint8_t*)frame, adtsHeader) < 0) {
		return -1;
	}

	// 读取AAC数据
	int aacFrameSize = adtsHeader->aacFrameLength - 7;
	if (aacFrameSize <= 0 || aacFrameSize > size - 7) {
		return -1;
	}

	if (fread(frame + 7, 1, aacFrameSize, fp) != aacFrameSize) {
		return -1;
	}

	return adtsHeader->aacFrameLength;
}

// 发送AAC帧
static int rtpSendAACFrame(int clientSockfd, struct RtpPacket* rtpPacket,
	char* frame, uint32_t frameSize, uint32_t* timestamp)
{
	// 设置RTP头
	rtpPacket->rtpHeader.timestamp = *timestamp;

	// 跳过ADTS头 (7字节)
	uint32_t aacDataSize = frameSize - 7;
	char* aacData = frame + 7;

	// 检查是否需要分片
	if (aacDataSize + 4 <= RTP_MAX_PKT_SIZE) {
		// 单一包模式
		rtpPacket->payload[0] = 0x00;
		rtpPacket->payload[1] = 0x10;
		rtpPacket->payload[2] = (aacDataSize & 0x1FE0) >> 5;
		rtpPacket->payload[3] = (aacDataSize & 0x1F) << 3;

		memcpy(rtpPacket->payload + 4, aacData, aacDataSize);

		int ret = rtpSendPacketOverTcp(clientSockfd, rtpPacket, aacDataSize + 4, 0x02);
		if (ret < 0) return -1;

		rtpPacket->rtpHeader.seq++;
		return ret;
	}
	else {
		// 分片模式 (AAC通常不需要分片)
		return -1;
	}
}

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
		char track[32] = { 0 };

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
			else if (strstr(line, "track")) {
				sscanf(line, "track: %31s", track);
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
			// 直接从已解析的url变量获取路径（不再重新解析line）
			printf("[DEBUG] SETUP URL: %s\n", url);

			// 统一处理URL路径（兼容有无/track0的情况）
			if (handleCmd_SETUP(clientSockfd, cseq, url) != 0) {
				printf("SETUP failed for URL: %s\n", url);
				break;
			}
		}
		else if (strcmp(method, "PLAY") == 0) {
			printf("Start streaming to %s:%d\n", clientIP, clientRtpPort);
			if (handleCmd_PLAY(clientSockfd, cseq) == 0) {
				sendMediaStream(clientSockfd);  // 开始发送媒体数据
			}
			else {
				printf("PLAY failed\n");
			}
			break;
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
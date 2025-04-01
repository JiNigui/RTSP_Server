#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "RTP.h"

void rtpHeaderInit(struct RtpPacket* rtpPacket, uint8_t csrcLen, uint8_t extension,
    uint8_t padding, uint8_t version, uint8_t payloadType, uint8_t marker,
    uint16_t seq, uint32_t timestamp, uint32_t ssrc)
{
    rtpPacket->rtpHeader.csrcLen = csrcLen;// 贡献源（CSRC）列表的长度。
    rtpPacket->rtpHeader.extension = extension;// 扩展字段的存在标志。
    rtpPacket->rtpHeader.padding = padding;// 填充字段的存在标志。
    rtpPacket->rtpHeader.version = version;// RTP版本号。
    rtpPacket->rtpHeader.payloadType = payloadType;// 负载类型。
    rtpPacket->rtpHeader.marker = marker;// 标记字段，用于指示重要帧（如关键帧）。
    rtpPacket->rtpHeader.seq = seq;// 序列号，用于数据包排序。
    rtpPacket->rtpHeader.timestamp = timestamp;// 时间戳，用于同步。
    rtpPacket->rtpHeader.ssrc = ssrc;// 同步源标识符，用于标识发送者。
}

int rtpSendPacketOverTcp(int clientSockfd, struct RtpPacket* rtpPacket, uint32_t dataSize)
{
    rtpPacket->rtpHeader.seq = htons(rtpPacket->rtpHeader.seq);
    rtpPacket->rtpHeader.timestamp = htonl(rtpPacket->rtpHeader.timestamp);
    rtpPacket->rtpHeader.ssrc = htonl(rtpPacket->rtpHeader.ssrc);

    uint32_t rtpSize = RTP_HEADER_SIZE + dataSize;// 计算RTP包的总大小（包括头部和负载）。
    char* tempBuf = (char*)malloc(4 + rtpSize);// 分配内存用于存储RTP包的临时缓冲区。
    tempBuf[0] = 0x24; // '$'
    tempBuf[1] = 0x00;
    tempBuf[2] = (uint8_t)(((rtpSize) & 0xFF00) >> 8);
    tempBuf[3] = (uint8_t)((rtpSize) & 0xFF);
    memcpy(tempBuf + 4, (char*)rtpPacket, rtpSize);// 将RTP包复制到临时缓冲区中。

    int ret = send(clientSockfd, tempBuf, 4 + rtpSize, 0);// 通过TCP发送RTP包。

    rtpPacket->rtpHeader.seq = ntohs(rtpPacket->rtpHeader.seq);
    rtpPacket->rtpHeader.timestamp = ntohl(rtpPacket->rtpHeader.timestamp);
    rtpPacket->rtpHeader.ssrc = ntohl(rtpPacket->rtpHeader.ssrc);

    free(tempBuf);
    tempBuf = NULL;

    return ret;
}

int rtpSendPacketOverUdp(int serverRtpSockfd, const char* ip, int16_t port,
    struct RtpPacket* rtpPacket, uint32_t dataSize)
{
    struct sockaddr_in addr;
    int ret;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    rtpPacket->rtpHeader.seq = htons(rtpPacket->rtpHeader.seq);
    rtpPacket->rtpHeader.timestamp = htonl(rtpPacket->rtpHeader.timestamp);
    rtpPacket->rtpHeader.ssrc = htonl(rtpPacket->rtpHeader.ssrc);

    ret = sendto(serverRtpSockfd, (char*)rtpPacket, dataSize + RTP_HEADER_SIZE, 0,
        (struct sockaddr*)&addr, sizeof(addr));

    rtpPacket->rtpHeader.seq = ntohs(rtpPacket->rtpHeader.seq);
    rtpPacket->rtpHeader.timestamp = ntohl(rtpPacket->rtpHeader.timestamp);
    rtpPacket->rtpHeader.ssrc = ntohl(rtpPacket->rtpHeader.ssrc);

    return ret;
}

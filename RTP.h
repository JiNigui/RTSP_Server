#ifndef _RTP_H_
#define _RTP_H_

#include <stdint.h>

#define RTP_HEADER_SIZE   12
#define RTP_VERSION       2
#define RTP_PAYLOAD_TYPE_H264 96
#define RTP_PAYLOAD_TYPE_AAC    97
#define RTP_MAX_PKT_SIZE  1400  // 最大RTP包大小

struct RtpHeader {
    uint8_t csrcLen : 4;
    uint8_t extension : 1;
    uint8_t padding : 1;
    uint8_t version : 2;
    uint8_t payloadType : 7;
    uint8_t marker : 1;
    uint16_t seq;
    uint32_t timestamp;
    uint32_t ssrc;
};

struct RtpPacket {
    struct RtpHeader rtpHeader;
    uint8_t payload[0];
};

// 初始化RTP头
void rtpHeaderInit(struct RtpPacket* rtpPacket, uint8_t csrcLen, uint8_t extension,
    uint8_t padding, uint8_t version, uint8_t payloadType, uint8_t marker,
    uint16_t seq, uint32_t timestamp, uint32_t ssrc);

// RTP包发送函数
int rtpSendPacketOverTcp(int clientSockfd, struct RtpPacket* rtpPacket, uint32_t dataSize);
int rtpSendPacketOverUdp(int serverRtpSockfd, const char* ip, int16_t port,
    struct RtpPacket* rtpPacket, uint32_t dataSize);

#endif // _RTP_H_
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "RTP.h"

void rtpHeaderInit(struct RtpPacket* rtpPacket, uint8_t csrcLen, uint8_t extension,
    uint8_t padding, uint8_t version, uint8_t payloadType, uint8_t marker,
    uint16_t seq, uint32_t timestamp, uint32_t ssrc)
{
    rtpPacket->rtpHeader.csrcLen = csrcLen;// ����Դ��CSRC���б�ĳ��ȡ�
    rtpPacket->rtpHeader.extension = extension;// ��չ�ֶεĴ��ڱ�־��
    rtpPacket->rtpHeader.padding = padding;// ����ֶεĴ��ڱ�־��
    rtpPacket->rtpHeader.version = version;// RTP�汾�š�
    rtpPacket->rtpHeader.payloadType = payloadType;// �������͡�
    rtpPacket->rtpHeader.marker = marker;// ����ֶΣ�����ָʾ��Ҫ֡����ؼ�֡����
    rtpPacket->rtpHeader.seq = seq;// ���кţ��������ݰ�����
    rtpPacket->rtpHeader.timestamp = timestamp;// ʱ���������ͬ����
    rtpPacket->rtpHeader.ssrc = ssrc;// ͬ��Դ��ʶ�������ڱ�ʶ�����ߡ�
}

int rtpSendPacketOverTcp(int clientSockfd, struct RtpPacket* rtpPacket, uint32_t dataSize)
{
    rtpPacket->rtpHeader.seq = htons(rtpPacket->rtpHeader.seq);
    rtpPacket->rtpHeader.timestamp = htonl(rtpPacket->rtpHeader.timestamp);
    rtpPacket->rtpHeader.ssrc = htonl(rtpPacket->rtpHeader.ssrc);

    uint32_t rtpSize = RTP_HEADER_SIZE + dataSize;// ����RTP�����ܴ�С������ͷ���͸��أ���
    char* tempBuf = (char*)malloc(4 + rtpSize);// �����ڴ����ڴ洢RTP������ʱ��������
    tempBuf[0] = 0x24; // '$'
    tempBuf[1] = 0x00;
    tempBuf[2] = (uint8_t)(((rtpSize) & 0xFF00) >> 8);
    tempBuf[3] = (uint8_t)((rtpSize) & 0xFF);
    memcpy(tempBuf + 4, (char*)rtpPacket, rtpSize);// ��RTP�����Ƶ���ʱ�������С�

    int ret = send(clientSockfd, tempBuf, 4 + rtpSize, 0);// ͨ��TCP����RTP����

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

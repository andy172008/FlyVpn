#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>



// # 打开ip转发功能
// echo 1 > /proc/sys/net/ipv4/ip_forward
//
// # 打开地址欺骗功能，将原地址为10.0.0.0/8的ip包都从eth0发出
// iptables -t nat -A POSTROUTING -s 10.0.0.0/8 -o eth0 -j MASQUERADE
//
// # 创建一个TUN接口
// ip tuntap add dev tun0 mode tun
//
// # 设置tun0
// ifconfig tun0 10.0.0.1 dstaddr 10.0.0.2 up
//
// # 对源程序编译（链接了openssl库，但来不及用上）
//g++ -Wall -o FLyVpnServer vpnserver.cpp -lcrypto
// 
// # 启动服务端程序
// ./FlyVpnServer tun0 8000 test -m 1400 -a 10.0.0.2 32 -d 8.8.8.8 -r 0.0.0.0 0


#include <net/if.h>
#include <linux/if_tun.h>

static int get_interface(char *name)
{
    //以读写方式、非阻塞方式打开
    int interface = open("/dev/net/tun", O_RDWR | O_NONBLOCK);

    ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    //点对点设备、不包含包信息
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));

    //打开设备
    if (ioctl(interface, TUNSETIFF, &ifr)) {
        perror("Cannot get TUN interface");
        exit(1);
    }

    return interface;
}



static int get_tunnel(char *port, char *secret)
{

    //SOCK_DGRAM：无保障的面向消息的socket
    int tunnel = socket(AF_INET6, SOCK_DGRAM, 0);
    int flag = 1;
    //SO_REUSEPORT支持多个进程或者线程绑定到同一端口，提高服务器程序的性能
    setsockopt(tunnel, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
    flag = 0;
    setsockopt(tunnel, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag));


    sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(atoi(port));


    //将本地地址与套接口绑定
    while (bind(tunnel, (sockaddr *)&addr, sizeof(addr))) {
        if (errno != EADDRINUSE) {
            return -1;
        }
        usleep(100000);
    }


    char packet[1024];
    socklen_t addrlen;
    do {
        addrlen = sizeof(addr);
        int n = recvfrom(tunnel, packet, sizeof(packet), 0,
                (sockaddr *)&addr, &addrlen);
        if (n <= 0) {
            return -1;
        }
        packet[n] = 0;
      //密钥匹配时，退出循环
    } while (packet[0] != 0 || strcmp(secret, &packet[1]));


    connect(tunnel, (sockaddr *)&addr, addrlen);
    return tunnel;
}

static void build_parameters(char *parameters, int size, int argc, char **argv)
{

    int offset = 0;
    for (int i = 4; i < argc; ++i) {
        char *parameter = argv[i];
        int length = strlen(parameter);
        char delimiter = ',';


        if (length == 2 && parameter[0] == '-') {
            ++parameter;
            --length;
            delimiter = ' ';
        }


        if (offset + length >= size) {
            puts("Parameters are too large");
            exit(1);
        }

        parameters[offset] = delimiter;
        memcpy(&parameters[offset + 1], parameter, length);
        offset += 1 + length;
    }


    memset(&parameters[offset], ' ', size - offset);


    parameters[0] = 0;
}

-----------------------------------------------------------------------------

int main(int argc, char **argv)
{
    if (argc < 5) {
        printf("Usage: %s <tunN> <port> <secret> options...\n"
               "\n"
               "Options:\n"
               "  -m <MTU> for the maximum transmission unit\n"
               "  -a <address> <prefix-length> for the private address\n"
               "  -r <address> <prefix-length> for the forwarding route\n"
               "  -d <address> for the domain name server\n"
               "  -s <domain> for the search domain\n"
               "\n"
               "Note that TUN interface needs to be configured properly\n"
               "BEFORE running this program. For more information, please\n"
               "read the comments in the source code.\n\n", argv[0]);
        exit(1);
    }


    //设置参数用
    char parameters[1024];
    build_parameters(parameters, sizeof(parameters), argc, argv);

    //创建TUN接口
    int interface = get_interface(argv[1]);

    //等待隧道建立
    int tunnel;
    while ((tunnel = get_tunnel(argv[2], argv[3])) != -1) {
        printf("%s: Here comes a new tunnel\n", argv[1]);

        
        //设置隧道为非s阻塞模式
        fcntl(tunnel, F_SETFL, O_NONBLOCK);

        //发送设置参数给服务器
        send(tunnel, parameters, sizeof(parameters), MSG_NOSIGNAL);
        

        
        char packet[32767];

        //计时用变量
        int timer = 0;

        // 一直循环，直到断开连接
        while (true) {
            
            bool idle = true;

            // Read the outgoing packet from the input stream.
            //从外部接口中读取数据
            int length = read(interface, packet, sizeof(packet));
            if (length > 0) {
                //将数据回传给手机
                send(tunnel, packet, length, MSG_NOSIGNAL);

                
                idle = false;

                
                if (timer < 1) {
                    timer = 1;
                }
            }

            // 从手机读取要发送的数据
            length = recv(tunnel, packet, sizeof(packet), 0);
            if (length == 0) {
                break;
            }
            if (length > 0) {
                
                write(interface, packet, length);
                

                idle = false;

                if (timer > 0) {
                    timer = 0;
                }
            }

          
            
            
            
            if (idle) {
                usleep(100000);

                //根据情况的不同，对timer执行不同的操作
                timer += (timer > 0) ? 100 : -100;


                if (timer > 20000 || timer < -20000) {
                    break;
                }
            }
        }
        printf("%s: The tunnel is broken\n", argv[1]);
        close(tunnel);
    }
    perror("Cannot create tunnels");
    exit(1);
}



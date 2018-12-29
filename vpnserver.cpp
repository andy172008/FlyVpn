

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
#include "mbedtls/md.h"

#include <iostream>  
#include <cassert>
#include <string>  
#include <vector>  
#include "openssl/md5.h"  
#include "openssl/sha.h"  
#include "openssl/des.h"  
#include "openssl/rsa.h"  
#include "openssl/pem.h" 
 




#include <net/if.h>
#include <linux/if_tun.h>
#include <fstream>
#include <iostream>
using namespace std;





#include <openssl/sha.h>
string sha256(const string str)
{
	char buf[2];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    std::string NewString = "";
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(buf,"%02x",hash[i]);
        NewString = NewString + buf;
    }
	return NewString;
}





static int get_interface(char *name)
{
    int interface = open("/dev/net/tun", O_RDWR | O_NONBLOCK);

    ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));

    if (ioctl(interface, TUNSETIFF, &ifr)) {
        perror("Cannot get TUN interface");
        exit(1);
    }

    return interface;
}




// ---- des对称加解密 ---- //  
// 加密 ecb模式  
std::string des_encrypt(const std::string &clearText, const std::string &key)
{
	std::string cipherText; // 密文  
 
	DES_cblock keyEncrypt;
	memset(keyEncrypt, 0, 8);
 
	// 构造补齐后的密钥  
	if (key.length() <= 8)
		memcpy(keyEncrypt, key.c_str(), key.length());
	else
		memcpy(keyEncrypt, key.c_str(), 8);
 
	// 密钥置换  
	DES_key_schedule keySchedule;
	DES_set_key_unchecked(&keyEncrypt, &keySchedule);
 
	// 循环加密，每8字节一次  
	const_DES_cblock inputText;
	DES_cblock outputText;
	std::vector<unsigned char> vecCiphertext;
	unsigned char tmp[8];
 
	for (int i = 0; i < clearText.length() / 8; i++)
	{
		memcpy(inputText, clearText.c_str() + i * 8, 8);
		DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_ENCRYPT);
		memcpy(tmp, outputText, 8);
 
		for (int j = 0; j < 8; j++)
			vecCiphertext.push_back(tmp[j]);
	}
 
	if (clearText.length() % 8 != 0)
	{
		int tmp1 = clearText.length() / 8 * 8;
		int tmp2 = clearText.length() - tmp1;
		memset(inputText, 0, 8);
		memcpy(inputText, clearText.c_str() + tmp1, tmp2);
		// 加密函数  
		DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_ENCRYPT);
		memcpy(tmp, outputText, 8);
 
		for (int j = 0; j < 8; j++)
			vecCiphertext.push_back(tmp[j]);
	}
 
	cipherText.clear();
	cipherText.assign(vecCiphertext.begin(), vecCiphertext.end());
 
	return cipherText;
}


// 解密 ecb模式  
std::string des_decrypt(const std::string &cipherText, const std::string &key)
{
	std::string clearText; // 明文  
 
	DES_cblock keyEncrypt;
	memset(keyEncrypt, 0, 8);
 
	if (key.length() <= 8)
		memcpy(keyEncrypt, key.c_str(), key.length());
	else
		memcpy(keyEncrypt, key.c_str(), 8);
 
	DES_key_schedule keySchedule;
	DES_set_key_unchecked(&keyEncrypt, &keySchedule);
 
	const_DES_cblock inputText;
	DES_cblock outputText;
	std::vector<unsigned char> vecCleartext;
	unsigned char tmp[8];
 
	for (int i = 0; i < cipherText.length() / 8; i++)
	{
		memcpy(inputText, cipherText.c_str() + i * 8, 8);
		DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_DECRYPT);
		memcpy(tmp, outputText, 8);
 
		for (int j = 0; j < 8; j++)
			vecCleartext.push_back(tmp[j]);
	}
 
	if (cipherText.length() % 8 != 0)
	{
		int tmp1 = cipherText.length() / 8 * 8;
		int tmp2 = cipherText.length() - tmp1;
		memset(inputText, 0, 8);
		memcpy(inputText, cipherText.c_str() + tmp1, tmp2);
		// 解密函数  
		DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_DECRYPT);
		memcpy(tmp, outputText, 8);
 
		for (int j = 0; j < 8; j++)
			vecCleartext.push_back(tmp[j]);
	}
 
	clearText.clear();
	clearText.assign(vecCleartext.begin(), vecCleartext.end());
 
	return clearText;
}


static int get_tunnel(char *port, char *secret)
{
    // We use an IPv6 socket to cover both IPv4 and IPv6.
    int tunnel = socket(AF_INET6, SOCK_DGRAM, 0);
    int flag = 1;

    const string strKey = secret;
    
    string rs = sha256(strKey);
    char crs[100];
    
    strcpy(crs,rs.c_str());
   // cout <<endl<<"crs:"<<crs<<endl;

    setsockopt(tunnel, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
    flag = 0;
    setsockopt(tunnel, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag));

    // Accept packets received on any local address.
    sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(atoi(port));

    // Call bind(2) in a loop since Linux does not have SO_REUSEPORT.
    while (bind(tunnel, (sockaddr *)&addr, sizeof(addr))) {
        if (errno != EADDRINUSE) {
            return -1;
        }
        usleep(100000);
    }

    // Receive packets till the secret matches.
    char packet[1024];
    socklen_t addrlen;
//cout << "gethere"<<endl;
    do {
        addrlen = sizeof(addr);
        int n = recvfrom(tunnel, packet, sizeof(packet), 0,
                (sockaddr *)&addr, &addrlen);
        if (n <= 0) {
            return -1;
        }
	packet[n] = 0;
        printf("packet  %s\n",packet + 1);
    } while (packet[0] != 0 || strcmp(crs, &packet[1]));

    // Connect to the client as we only handle one client at a time.
    connect(tunnel, (sockaddr *)&addr, addrlen);
    return tunnel;
}

static void build_parameters(char *parameters, int size, int argc, char **argv)
{
    // Well, for simplicity, we just concatenate them (almost) blindly.
    int offset = 0;
    for (int i = 4; i < argc; ++i) {
        char *parameter = argv[i];
        int length = strlen(parameter);
        char delimiter = ',';

        // If it looks like an option, prepend a space instead of a comma.
        if (length == 2 && parameter[0] == '-') {
            ++parameter;
            --length;
            delimiter = ' ';
        }

        // This is just a demo app, really.
        if (offset + length >= size) {
            puts("Parameters are too large");
            exit(1);
        }

        // Append the delimiter and the parameter.
        parameters[offset] = delimiter;
        memcpy(&parameters[offset + 1], parameter, length);
        offset += 1 + length;
    }

    // Fill the rest of the space with spaces.
    memset(&parameters[offset], ' ', size - offset);

    // Control messages always start with zero.
    parameters[0] = 0;
}


string getTime()
 {
      time_t timep;
      time (&timep);
      char tmp[64];
     strftime(tmp, sizeof(tmp), "%Y-%m-%d %H:%M:%S",localtime(&timep) );
     return tmp;
 }



//-----------------------------------------------------------------------------

int main(int argc, char **argv)
{
  // cout << sha256("test"); 
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

    // Parse the arguments and set the parameters.
    char parameters[1024];
    build_parameters(parameters, sizeof(parameters), argc, argv);

    // Get TUN interface.
    int interface = get_interface(argv[1]);

    // Wait for a tunnel.
    int tunnel;
    while ((tunnel = get_tunnel(argv[2], argv[3])) != -1) {
        printf("%s: Here comes a new tunnel\n", argv[1]);

	char* userNamechar = argv[3];	
	string userName(userNamechar);
	string logAdd = userName + "log.txt";

	cout << logAdd << endl;
	ofstream userLog;
        userLog.open("user.log");

	userLog << getTime();
	userLog << "user" << argv[3] << " is login "<<endl;
        // On UN*X, there are many ways to deal with multiple file
        // descriptors, such as poll(2), select(2), epoll(7) on Linux,
        // kqueue(2) on FreeBSD, pthread(3), or even fork(2). Here we
        // mimic everything from the client, so their source code can
        // be easily compared side by side.
  //      cout << "here3";
        // Put the tunnel into non-blocking mode.
        fcntl(tunnel, F_SETFL, O_NONBLOCK);

       
        // Send the parameters several times in case of packet loss.
       // for (int i = 0; i < 3; ++i) {
            send(tunnel, parameters, sizeof(parameters), MSG_NOSIGNAL);
      //  }

        // Allocate the buffer for a single packet.
        char packet[32767];

        // We use a timer to determine the status of the tunnel. It
        // works on both sides. A positive value means sending, and
        // any other means receiving. We start with receiving.
        int timer = 0;


        // We keep forwarding packets till something goes wrong.
        while (true) {
            // Assume that we did not make any progress in this iteration.
            bool idle = true;

            // Read the outgoing packet from the input stream.
            int length = read(interface, packet, sizeof(packet));
            if (length > 0) {
                // Write the outgoing packet to the tunnel.
  //              cout << "user "<<argv[3]<< "has send package with length "<<length ;
//		packet[0] ^= 1;
		send(tunnel, packet, length, MSG_NOSIGNAL);
//		printf("user test\n");
		userLog << getTime();
		userLog << " user "<<argv[3]<< " has receive package with length "<<length<<endl ;
                // There might be more outgoing packets.
                idle = false;

                // If we were receiving, switch to sending.
                if (timer < 1) {
                    timer = 1;
                }
            }

            // Read the incoming packet from the tunnel.
            length = recv(tunnel, packet, sizeof(packet), 0);
            if (length == 0) {
                break;
            }
            if (length > 0) {
                // Ignore control messages, which start with zero.
                if (packet[0] != 0) {
                    // Write the incoming packet to the output stream.
                    write(interface, packet, length);
		    userLog << getTime();
		    userLog << " user "<<argv[3]<<" has send package with length "<<length<<endl;
                }

                // There might be more incoming packets.
                idle = false;

                // If we were sending, switch to receiving.
                if (timer > 0) {
                    timer = 0;
                }
            }

            // If we are idle or waiting for the network, sleep for a
            // fraction of time to avoid busy looping.
            if (idle) {
                usleep(100000);

                // Increase the timer. This is inaccurate but good enough,
                // since everything is operated in non-blocking mode.
                timer += (timer > 0) ? 100 : -100;

                // We are receiving for a long time but not sending.
                // Can you figure out why we use a different value? :)
/*
                if (timer < -16000) {
                    // Send empty control messages.
                    packet[0] = 0;
                    for (int i = 0; i < 3; ++i) {
                        send(tunnel, packet, 1, MSG_NOSIGNAL);
                    }

                    // Switch to sending.
                    timer = 1;
                }
*/
                // We are sending for a long time but not receiving.
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


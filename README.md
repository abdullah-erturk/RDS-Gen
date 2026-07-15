<div align=>
    
<a href="https://buymeacoffee.com/abdullaherturk" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>

# RDS Gen 🔑

![sample](https://github.com/abdullah-erturk/RDS-Gen/blob/main/RDSGen.jpg)

## Download Link:

[![Stable?](https://img.shields.io/badge/Release-v4.svg?style=flat)](https://github.com/abdullah-erturk/RDS-Gen/archive/refs/heads/main.zip)

<br>
<details>
<summary><strong>📋 Değişiklikler / Changelog</strong></summary>

| Version | Changelog |
| :---: | :--- |
| **v1** | 🇹🇷 İlk Sürüm <hr> 🇬🇧 First Release |
| **v2** | 🇹🇷 Karanlık tema arayüzü, uygulama içi dil seçeneği (EN/TR), lisans sıfırlama aracı entegrasyonu ve çıktı kutusu düzeltmeleri eklendi. <hr> 🇬🇧 Dark Theme GUI, in-app language toggle (EN/TR), integrated license reset tool, and output box fixes added. |
| **v3** | 🇹🇷 İşletim sistemi güvenlik kontrolü eklendi (İşlemlerin Windows 10/11'de hataya yol açmasını engeller). <hr> 🇬🇧 Added OS validation check (prevents feature errors on non-server OS like Win 10/11). |
| **v4** | 🇹🇷 Yanlış (Windows OS) PID çeken büyüteç butonunun RDS Lisans Sunucusu PID otomatik algılama mantığı düzeltildi. Arayüz donmalarını önlemek için RDS kaldır/kur işlemleri bağımsız konsol (external run) mimarisine taşındı ve menü dil çevirilerindeki hatalar giderildi. <hr> 🇬🇧 Fixed automatic RDS License Server PID detection (it now fetches the correct RDS PID instead of the OS PID). Moved RDS install/uninstall operations to an independent console architecture to prevent GUI freezing, and fixed context menu language bugs. |

</details>

</div>

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)
![C#](https://img.shields.io/badge/C%23-Inline-green.svg)
![Windows](https://img.shields.io/badge/OS-Windows-lightgrey.svg)

<details>
<summary><b>Türkçe 🇹🇷</b></summary>

## Genel Bakış
**RDS Gen**, Microsoft Uzak Masaüstü Hizmetleri (RDS) ve İstemci Erişim Lisanslarının (CAL) çevrimdışı aktivasyon sürecinde kullanılan **Lisans Sunucu Kimliği (SPK)** ve **Lisans Anahtar Paketi (LKP)** kodlarını üretmek için tasarlanmış, grafik arayüzlü (GUI) bağımsız bir PowerShell/C# betiğidir.

Web tabanlı alternatiflerinin aksine, bu araç tamamen bilgisayarınızda yerel olarak çalışır ve internet bağlantısı gerektirmez.

## Teknik Temel
Bu proje, **[WitherOrNot](https://github.com/WitherOrNot)** tarafından yapılan temel kriptografik araştırmalara dayanmaktadır. WitherOrNot, bu araştırmasıyla Python dilinde bir PoC (Kavram Kanıtı) komut satırı aracı geliştirmiştir (orijinal haline [GitHub Gist](https://gist.github.com/WitherOrNot/c34c4c7b893e89ab849ce04e007d89a9) üzerinden ulaşılabilir).
Kriptografi kodlarının C# diline uyarlanması ve ilk web arayüzünün oluşturulması ise **[Lyssa (thecatontheceiling)](https://github.com/thecatontheceiling)** tarafından yapılmıştır.

## Yasal Uyarı / Eğitim Amacı
Bu çalışma tamamen **eğitim ve araştırma amacıyla** hazırlanmıştır. Lütfen bu aracı kullanırken Microsoft'un mevcut lisans sözleşmelerine ve kullanım şartlarına (EULA) uyunuz. Geliştiriciler, bu aracın amacı dışında kullanılmasından doğacak herhangi bir yasal sorumluluğu kabul etmez.

## Ekstra: RDS Lisanslamasını Tamamen Sıfırlama
**💡 Not:** Bu işlemlerin tamamı uygulamanın yeni sürümüyle birlikte doğrudan arayüze entegre edilmiştir. Ancak işlemleri manuel olarak yapmak isterseniz, Yönetici olarak (Administrator) PowerShell'i açıp aşağıdaki adımları uygulayabilirsiniz:

```powershell
# 1. Servisi durdur
Stop-Service TermServLicensing -Force -ErrorAction SilentlyContinue
taskkill /F /FI "SERVICES eq TermServLicensing" 2>$null
Start-Sleep -Seconds 2

# 2. Rolü tamamen kaldır (bu, servis kaydını, COM bileşenlerini, registry şablonlarını da temizler)
Uninstall-WindowsFeature -Name RDS-Licensing -Restart

# 3. Kalan izleri temizle (varsa)
Remove-Item "C:\Windows\System32\lserver" -Recurse -Force -ErrorAction SilentlyContinue
reg delete "HKLM\SOFTWARE\Microsoft\TermServLicensing" /f 2>$null
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\TermServLicensing" /f 2>$null

# 4. Rolün tamamen gittiğini doğrula
Get-WindowsFeature -Name RDS-Licensing

# 5. Bilgisayarı yeniden başlat.

# 6. Rolü sıfırdan kur
Install-WindowsFeature -Name RDS-Licensing -IncludeManagementTools -Restart

# 7. Servisi başlat
Start-Service TermServLicensing
```

## Teşekkürler
Katkılarından ve muazzam çalışmalarından dolayı aşağıdaki kişilere özel teşekkürler:
* **[WitherOrNot](https://github.com/WitherOrNot)** - Temel kriptografi araştırması ve orijinal kod katkıları.
* **[Lyssa (thecatontheceiling)](https://github.com/thecatontheceiling)** - Kodun C# uyarlaması ve web tabanlı temel proje.
* **[asdcorp](https://github.com/asdcorp)** - Orijinal projenin temellerine olan katkıları.
* **[Bensuslu11](https://github.com/Bensuslu11)** - Arayüz (GUI) güncellemesindeki harika katkıları.

*Kullanıcı arayüzü ve PowerShell entegrasyonu [Abdullah ERTÜRK](https://github.com/abdullah-erturk) tarafından kodlanmıştır.*
</details>

---

<details >
<summary><b>English 🇬🇧</b></summary>

## Overview
**RDS Gen** is a standalone, hybrid PowerShell/C# script with a graphical user interface (GUI) designed for the generation of **Service Provider Keys (SPKs)** (License Server IDs) and **License Key Packs (LKPs)**. These keys are utilized in the offline activation process for Microsoft Remote Desktop Services (RDS) and associated Client Access Licenses (CALs). 

Unlike web-based implementations, this tool runs entirely locally on your Windows machine without requiring internet access.

## Technical Basis
This project leverages the foundational cryptographic research conducted by **[WitherOrNot](https://github.com/WitherOrNot)**, who developed the original Proof-of-Concept CLI tool in Python (available in his [GitHub gist](https://gist.github.com/WitherOrNot/c34c4c7b893e89ab849ce04e007d89a9)). 
The C# cryptography port was originally created by **[Lyssa (thecatontheceiling)](https://github.com/thecatontheceiling)**.

## Disclaimer / Educational Purpose
This project is strictly for **educational and research purposes**. Please adhere to Microsoft's current licensing agreements and terms of use (EULA) when using this tool. The developers assume no legal responsibility for any misuse of this tool.

## Extra: Completely Resetting RDS Licensing
**💡 Note:** All of these steps are now integrated directly into the application's GUI in the latest release. However, if you wish to perform them manually, you can run the following PowerShell commands as Administrator:

```powershell
# 1. Stop the service
Stop-Service TermServLicensing -Force -ErrorAction SilentlyContinue
taskkill /F /FI "SERVICES eq TermServLicensing" 2>$null
Start-Sleep -Seconds 2

# 2. Completely remove the role (this also cleans up service registration, COM components, and registry templates)
Uninstall-WindowsFeature -Name RDS-Licensing -Restart

# 3. Clean up remaining traces (if any)
Remove-Item "C:\Windows\System32\lserver" -Recurse -Force -ErrorAction SilentlyContinue
reg delete "HKLM\SOFTWARE\Microsoft\TermServLicensing" /f 2>$null
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\TermServLicensing" /f 2>$null

# 4. Verify the role is completely removed
Get-WindowsFeature -Name RDS-Licensing

# 5. Restart the computer.

# 6. Reinstall the role from scratch
Install-WindowsFeature -Name RDS-Licensing -IncludeManagementTools -Restart

# 7. Start the service
Start-Service TermServLicensing
```

## Acknowledgements
A special thanks to the following individuals for their amazing work and contributions:
* **[WitherOrNot](https://github.com/WitherOrNot)** - Foundational research and original code contributions.
* **[Lyssa (thecatontheceiling)](https://github.com/thecatontheceiling)** - Original C# port and the base web implementation.
* **[asdcorp](https://github.com/asdcorp)** - Contributions to the foundation of the original project.
* **[Bensuslu11](https://github.com/Bensuslu11)** - Awesome contributions to the user interface (GUI) updates.

*GUI and PowerShell integration coded by [Abdullah ERTÜRK](https://github.com/abdullah-erturk).*
</details>

# 

<div align="center">

<p align="center">
  <b>Developed by Abdullah ERTÜRK</b><br>
  <a href="https://erturk-dev.netlify.app" target="_blank">erturk-dev.netlify.app</a> | <a href="https://github.com/abdullah-erturk" target="_blank">github.com/abdullah-erturk</a>
</p>
</div>

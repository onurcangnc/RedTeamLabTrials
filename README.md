# RedTeamLabTrials

**EDR Atlatma Araştırmaları — AMSI/ETW Bypass + Win32 Native Dosya İşlemleri C# ile**

> ⚠️ **Yalnızca Yetkili Kullanım.** Bu depo, eğitim amaçlı ve yetkili red-team araştırmaları için konsept kanıtı uygulamalar içerir. Sahibi olmadığınız veya açık izniniz bulunmayan sistemlere karşı yetkisiz kullanım yasa dışıdır.

---

## Genel Bakış

Windows saldırı güvenliği araç geliştirme için araştırma ortamı. Şunları gösterir:

- **AMSI Yama** — Çalışma zamanı bellek değişikliği ile `AmsiScanBuffer`'ı bypass etme
- **ETW Yama** — `ntdll.dll` bellek yaması ile `EtwEventWrite`'ı devre dışı bırakma
- **Native Win32 G/Ç** — Yönetilen kod izlemeyi bypass etmek için ham Win32 API ile dosya işlemleri
- **Tanı Araçları** — SAM/LSA/SSH/WiFi numaralamayı gösteren sistem erişim modülleri

---

## Depo İçeriği

| Dosya | Açıklama |
|-------|----------|
| `EdrEvader.cs` | XOR ile gizlenmiş yollar ve native Win32 dosya yazma ile AMSI + ETW çift yaması |
| `EdrEvader_NoObfuscation.cs` | Dize gizlemesi olmadan aynı teknik (karşılaştırma taban çizgisi) |
| `sam_lsa_wifi_ssh.cs` | Sistem tanı aracı — SAM kayıt defteri, LSA sırları, SSH anahtar keşfi, WiFi profili çıkarma |

---

## Teknik Detaylar

### AMSI Yaması

`AmsiScanBuffer`'ı her zaman `AMSI_RESULT_CLEAN` döndürecek şekilde yamalar:

```
mov eax, 0x00005700    ; AMSI_RESULT_CLEAN
ret
```

### ETW Yaması

`ntdll.dll` içinde `EtwEventWrite`'ı devre dışı bırakır:

```
ret                     ; 0xC3 (anında dönüş)
```

### Neden Ham Win32 API?

Standart `System.IO` yöntemleri genellikle EDR/AV tarafından CLR seviyesinde hooklanır. Ham `CreateFile` → `WriteFile` → `CloseHandle`, yönetilen kod enstrümantasyonunun altında çalışır.

---

## Derleme Gereksinimleri

- Windows İşletim Sistemi (API'ye özgü işlevsellik)
- .NET 6.0+ SDK veya `csc` derleyicisi
- Yönetici ayrıcalıkları (AMSI/ETW yaması ve tanı modülleri için)

```bash
csc EdrEvader.cs -out:EdrEvader.exe
```

---

## Tespit Rehberi (Mavi Takım)

| Teknik | Tespit Kaynağı |
|--------|----------------|
| AMSI yaması | `amsi.dll` üzerinde `VirtualProtect` (Sysmon EID 10/11); `Microsoft-Windows-Amsi` olaylarının kaybolması |
| ETW yaması | Eksik `EtwEventWrite` geri çağrımları; sessiz güvenlik sağlayıcıları |
| SAM erişimi | `HKLM\SAM\SAM\Domains\Account\Users` üzerinde `RegOpenKeyEx` (Sysmon EID 12/13) |
| LSA sırları | Alışılmadık gizli adlarla `LsaRetrievePrivateData` çağrıları |
| SSH anahtar okuma | `%USERPROFILE%\.ssh\id_*` dosyalarında okuma (Sysmon EID 11) |
| WiFi çıkarma | `WLAN_PROFILE_GET_PLAINTEXT_KEY` bayrağı ile `WlanGetProfile` |

---

## Sorumluluk Reddi

Bu materyal **yalnızca yetkili güvenlik testi, tespit mühendisliği ve eğitim amaçlıdır.** Yazarlar kötüye kullanımdan sorumlu değildir. Yetkili test ile yasa dışı faaliyet arasındaki farkı ayırt edemiyorsanız, bu kodu kullanmayın.

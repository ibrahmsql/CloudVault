# CloudVault - Screenshot Commands

## 📸 En İyi Görsel Komutlar (README için)

Terminal'de çalıştır ve screenshot al:

### 1. 📊 Dashboard (Risk Overview)
```bash
cloudvault dashboard -i test_findings.json --filter "severity=CRITICAL,HIGH"
```
**Neden:** Renkli gauge, tablolar, grafikler - en görsel!

### 2. 🌳 Attack Chain Analysis
```bash
cloudvault analyze -i test_findings.json -f tree --min-blast-radius 50
```
**Neden:** Güzel tree visualization + MITRE mapping

### 3. 📋 Compliance Report
```bash
cloudvault compliance -i test_findings.json --framework CIS
```
**Neden:** Pass/Fail gösterimi + kontrol listesi

### 4. 🔍 Cloud Fingerprinting
```bash
cloudvault recon fingerprint -u https://aws.amazon.com -u https://storage.googleapis.com
```
**Neden:** Multi-provider detection gösterimi

### 5. 🔧 Auto-Remediation
```bash
cloudvault remediate -i test_findings.json -f terraform --dry-run
```
**Neden:** Terraform code generation

### 6. 🐳 Container Registry Scan
```bash
cloudvault recon containers --dockerhub library
```
**Neden:** Registry enumeration

---

## 💡 Screenshot Alma:

**macOS:**
1. Terminal'i tam ekran yap
2. Komutu çalıştır
3. `Cmd + Shift + 4` → Space → Terminal tıkla

**Kaydet:**
```
screenshots/
├── dashboard.png
├── analyze.png
├── compliance.png
├── recon-fingerprint.png
├── remediate.png
└── containers.png
```

---

## 📝 README'ye Ekle:

```markdown
## 📸 Screenshots

### Security Dashboard
![Dashboard](screenshots/dashboard.png)

### Attack Chain Analysis  
![Analyze](screenshots/analyze.png)

### Compliance Audit
![Compliance](screenshots/compliance.png)

### Cloud Fingerprinting
![Recon](screenshots/recon-fingerprint.png)

### Auto-Remediation
![Remediate](screenshots/remediate.png)

### Container Registry Scan
![Containers](screenshots/containers.png)
```

---

## ✨ Bonus: GIF Kaydı

**Asciinema ile kayıt:**
```bash
asciinema rec cloudvault-demo.cast
# Komutları çalıştır
# Ctrl+D ile bitir

# GIF'e çevir
agg cloudvault-demo.cast cloudvault-demo.gif
```

Bunu README'ye ekle:
```markdown
## 🎬 Demo
![CloudVault Demo](cloudvault-demo.gif)
```

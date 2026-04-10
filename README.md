<p align="center">
<img src="https://readme-typing-svg.herokuapp.com?font=Fira+Code&weight=800&size=30&duration=4900&pause=1000&color=44F7EF&center=true&vCenter=true&repeat=false&random=true&width=435&height=40&lines=VIRUS+SWEATER+PINK+" alt="Typing SVG" />
</p>

```
sudo sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/; s/^#\?PasswordAuthentication.*/PasswordAuthentication yes/; s/^#\?PubkeyAuthentication.*/#PubkeyAuthentication yes/' /etc/ssh/sshd_config && (sudo systemctl restart ssh || sudo systemctl restart sshd)
```

```
sudo su <<'EOF'
# Set SSH config
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#\?PubkeyAuthentication.*/#PubkeyAuthentication yes/' /etc/ssh/sshd_config

# Restart SSH
systemctl restart ssh || systemctl restart sshd

exit
EOF
```

```
grep -E "PermitRootLogin|PasswordAuthentication|PubkeyAuthentication" /etc/ssh/sshd_config
```

```
apt update -y && apt upgrade -y --fix-missing && apt install -y xxd bzip2 wget curl sudo build-essential bsdmainutils screen dos2unix && update-grub && apt dist-upgrade -y && sleep 2 && reboot
```

```
screen -S setup-session bash -c "wget -q https://raw.githubusercontent.com/sweaterpink1999/install-sh/main/install.sh && chmod +x install.sh && ./install.sh; read -p 'Tekan enter untuk keluar...'"
```
## Perintah Untuk Update Script
```
wget -q -O update.sh https://raw.githubusercontent.com/sweaterpink1999/os/main/update.sh && chmod +x update.sh && ./update.sh && rm -f update.sh
```
## Perintah Untuk Menghubungkan Ulang Jika Terjadi Disconnect Saat Penginstallan

```
screen -r -d setup
```
### edit os langsung
```
sudo nano /usr/local/bin/namefile
```
```
sudo nano /usr/local/bin/ws-stunnel
```
## FIX NGINX
```
sed -i '/\[::\]/s/^/#/' /etc/nginx/conf.d/xray.conf
nginx -t

Harus keluar:

nginx: configuration file /etc/nginx/nginx.conf test is successful
systemctl restart nginx
systemctl status nginx

systemctl restart xray
menu
```
```
mkdir -p /etc/xray
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
-keyout /etc/xray/xray.key -out /etc/xray/xray.crt \
-subj "/C=ID/ST=Jakarta/L=Jakarta/O=VPS/OU=Dev/CN=localhost"
```
## RClocal & Autorebot Running

```
cat /etc/rc.local
```
```
chmod +x /etc/rc.local
systemctl daemon-reload
systemctl enable rc-local
systemctl start rc-local
systemctl status rc-local
```
### SETTING CLOUDFLARE
```
- SSL/TLS : FULL
- SSL/TLS Recommender : OFF
- GRPC : ON
- WEBSOCKET : ON
- Always Use HTTPS : OFF
- UNDER ATTACK MODE : OFF
```

### `WARNING !`
```
Jika Mendapatkan Status Service Off
Silahkan Restart Service.
Jika Statsus Service Masih Off
Silahkan Reboot vps kalian
```

### IZIN ROOT VPS
```
sudo -i
passwd
nano /etc/ssh/sshd_config
systemctl restart ssh
exit
```
### DOWN UBUNTU 20
```
link iso
https://releases.ubuntu.com/20.04/ubuntu-20.04.6-live-server-amd64.iso

nano /etc/apt/sources.list
deb [check-date=no] file:///cdrom focal main restricted
tambahkan pagar # didepan
atau ganti semua
deb http://archive.ubuntu.com/ubuntu focal main universe restricted multiverse
deb http://archive.ubuntu.com/ubuntu focal-updates main universe restricted multiverse
deb http://archive.ubuntu.com/ubuntu focal-security main universe restricted multiverse

apt update && apt install openssh-server -y
```
### DOWN UBUNTU SC ROOT 20
```
curl -O https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh && bash reinstall.sh ubuntu 20.04 && reboot
```
### update xray core
```
https://github.com/XTLS/Xray-core/releases
```
```
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version 25.5.16
```
```
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data
```
### edit drive token backup
```
nano /root/.config/rclone/rclone.conf
```
### STAK VPS LAMA
```
pkill -9 apt apt-get apt-check
rm -f /var/lib/apt/lists/lock /var/lib/dpkg/lock /var/lib/dpkg/lock-frontend
dpkg --configure -a
apt update -y && apt upgrade -y --fix-missing && apt install -y xxd bzip2 wget curl sudo build-essential bsdmainutils screen dos2unix && update-grub && apt dist-upgrade -y && sleep 2 && reboot
```

### key ssh
```
mkdir -p ~/.ssh
nano ~/.ssh/authorized_keys
```
```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCCLHDIFydk/1IhLf4sdEMPK1LVUPVjZMUFJiKvlq5QkxTMeZ9+FpDcUcIRdm+q7m32blUZOmdi7c6yOuLGdLLHCBz5jq94QYsp9+JJSrEsXzNPRO4pAk2R/1njgE5pnprJeB00NT7v7OJ2aWQ2LcJsR7eEQjJVR7X/zbEsQx6iNhSjOh35iCYqCzEum7q2fMhk+5pgfSyXUGZmjqpgojbdxCnHR59R/qTdZbHbSULrmjIT/qJUm6aFVqF7JMqAPfqBTOD6gi0L9GquCpUw2r0FisEWhlJB5HXA+0sdxnVIdOsd5pE3C539jPbT0r5YpcKk2PF04VXIt6Ug80YaNJgP rsa-key-20251008
```

### ganti logo connect ws ssh
```
nano /usr/local/bin/ws-stunnel
```
### token backup
```
rclone config reconnect drive:
```
Jawab seperti ini:

Already have token – refresh? → y

Use auto config? → n

Copy link Google

Buka di HP / PC

Login → Allow

Paste verification code

Shared drive? → n

Simpan → y

Keluar → q
### CEK LOKAL VPS
```
curl ipinfo.io
```
### root vps bandel bizgo
2️⃣ Buka authorized_keys root
```
nano /root/.ssh/authorized_keys
```
3️⃣ CARI baris seperti ini (PENTING)
```
command="echo 'Please login as the user udpzip rather than the user root.'"
```
4️⃣ PERBAIKI (INI KUNCI SUKSES)

❌ HAPUS HANYA bagian command="..."

masukan key ppk putty contoh:

ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...

agar bisa login root di jus ganti yes
```
sudo nano /etc/ssh/sshd_config.d/50-cloud-init.conf
```
```
PasswordAuthentication yes
```


⚠️ Jangan hapus key-nya, hanya command-nya

### insatall jq jika error
```
apt update
apt install -y jq
```
```
jq --version
```

### (windows powersell - WSL - UBuntu) SET MENU 
```
cd /mnt/c/Users/Lukman/Downloads/menu/menu
```
```
./menu
```

### WORK DI OS
- UBUNTU 20.04.05
- DEBIAN 10 ( Disarankan )

### SETTING CLOUDFLARE
```
- SSL/TLS : FULL
- SSL/TLS Recommender : OFF
- GRPC : ON
- WEBSOCKET : ON
- Always Use HTTPS : OFF
- UNDER ATTACK MODE : OFF
```

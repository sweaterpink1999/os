#!/bin/bash
# =========================================
#         OS-MAIN UPDATE UTILITY
#     Version 6.3 - Full Replace Mode
# =========================================

# Warna tampilan
BIWhite='\033[1;97m'
BIGreen='\033[1;92m'
BIRed='\033[1;91m'
BIYellow='\033[1;93m'
bggreen='\e[42;97;1m'
NC='\033[0m'

# Lokasi & Repo
REPO="https://raw.githubusercontent.com/sweaterpink1999/os/main"
VERSION_FILE="/usr/local/sbin/.last_update"
SELF_PATH="/usr/local/sbin/update.sh"

# =========================================
# 0️⃣ SIMPAN DIRI PERMANEN DI /usr/local/sbin/
# =========================================
if [ "$(realpath "$0")" != "$SELF_PATH" ]; then
    mkdir -p /usr/local/sbin
    cp -f "$0" "$SELF_PATH"
    chmod +x "$SELF_PATH"
    echo -e "${BIGreen}✅ Script disalin ke lokasi permanen: $SELF_PATH${NC}"
fi

# =========================================
# 1️⃣ AUTO UPDATE DIRI SENDIRI DARI GITHUB
# =========================================
echo -e "${BIYellow}[INFO] Mengecek versi terbaru...${NC}"
TMP="/tmp/update_latest.sh"
wget -q -O "$TMP" "${REPO}/update.sh"

if [ -s "$TMP" ]; then
    if ! cmp -s "$TMP" "$SELF_PATH"; then
        echo -e "${BIYellow}🔄 Versi baru ditemukan — memperbarui script utama...${NC}"
        cp -f "$TMP" "$SELF_PATH"
        chmod +x "$SELF_PATH"
        echo -e "${BIGreen}✅ Script berhasil diperbarui.${NC}"
        sleep 1
        exec "$SELF_PATH"   # Jalankan ulang versi terbaru
    else
        echo -e "${BIGreen}✅ Script sudah versi terbaru.${NC}"
    fi
else
    echo -e "${BIRed}⚠️ Gagal mengambil versi terbaru dari GitHub.${NC}"
fi
rm -f "$TMP"

# =========================================
# 2️⃣ LOADING BAR ANIMASI
# =========================================
fun_bar() {
    tput civis
    echo -ne "\033[1;33mLoading\033[1;37m - \033[0;33m["
    for ((i=0; i<25; i++)); do
        echo -ne "\033[1;32m#"
        sleep 0.05
    done
    echo -e "\033[0;33m]\033[1;37m -\033[1;32m OK\033[1;37m"
    tput cnorm
}

# =========================================
# 3️⃣ UPDATE FILE MENU DAN REPLACE FILE LAMA
# =========================================
update_files() {
    echo ""
    echo "[INFO] Mengunduh file terbaru..."
    cd /tmp || exit 1
    wget -q -O menu.zip "${REPO}/menu/menu.zip"

    if [ ! -s "menu.zip" ]; then
        echo -e "${BIRed}❌ Gagal mengunduh file menu.zip dari repo.${NC}"
        return 1
    fi

    unzip -o menu.zip >/dev/null 2>&1

    if [ -d "menu" ]; then
        echo "[INFO] Menghapus file lama di /usr/local/sbin ..."
        # Hapus semua file terkait menu & utilitas lama
        find /usr/local/sbin -maxdepth 1 -type f \( \
            -name "menu*" -o -name "fix-*" -o -name "add*" -o -name "backup*" -o -name "bot*" -o -name "menu" \
        \) -exec rm -f {} \; >/dev/null 2>&1
        sleep 1

        echo "[INFO] Memindahkan file baru dari folder 'menu/' ..."
        chmod +x menu/* >/dev/null 2>&1
        mv -f menu/* /usr/local/sbin/ >/dev/null 2>&1
        dos2unix /usr/local/sbin/* >/dev/null 2>&1
        chmod +x /usr/local/sbin/* >/dev/null 2>&1

        echo -e "${BIGreen}[OK] Semua file berhasil diperbarui dari folder 'menu/'.${NC}"
    else
        echo -e "${BIRed}❌ Struktur ZIP salah — folder 'menu/' tidak ditemukan.${NC}"
    fi

    rm -rf /tmp/menu /tmp/menu.zip
    date '+%Y-%m-%d %H:%M:%S' > "$VERSION_FILE"
}

# =========================================
# 4️⃣ VERIFIKASI SISTEM
# =========================================
verify_services() {
    echo ""
    echo "[INFO] Memverifikasi layanan sistem..."
    sleep 1
    systemctl daemon-reload
    systemctl enable rc-local >/dev/null 2>&1
    systemctl restart rc-local >/dev/null 2>&1
    systemctl enable cron >/dev/null 2>&1
    systemctl restart cron >/dev/null 2>&1

    [[ $(systemctl is-active rc-local) == "active" ]] && \
        echo -e "✅ RC.local  : ${BIGreen}Running${NC}" || \
        echo -e "❌ RC.local  : ${BIRed}Tidak aktif${NC}"

    [[ $(systemctl is-active cron) == "active" ]] && \
        echo -e "✅ Cron      : ${BIGreen}Running${NC}" || \
        echo -e "❌ Cron      : ${BIRed}Tidak aktif${NC}"
}

# =========================================
# 5️⃣ TAMPILAN UTAMA
# =========================================
clear
echo -e "${BIWhite}──────────────────────────────────────${NC}"
echo -e "${bggreen}             UPDATE SCRIPT            ${NC}"
echo -e "${BIWhite}──────────────────────────────────────${NC}"
echo ""

fun_bar
update_files
verify_services

# =========================================
# 6️⃣ PENUTUP
# =========================================
echo -e "${BIWhite}──────────────────────────────────────${NC}"
if [ -f "$VERSION_FILE" ]; then
    echo ""
    echo -e "📅 ${BIYellow}Waktu Update Terakhir:${NC} ${BIGreen}$(cat $VERSION_FILE)${NC}"
fi
echo ""
echo -e "${BIYellow}Jika tidak ada perubahan, sistem Anda sudah versi terbaru.${NC}"
echo ""
read -n 1 -s -r -p "Press [ Enter ] to back on menu"
clear
menu

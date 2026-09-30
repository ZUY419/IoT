#!/bin/bash
# ================= 設定區 =================
firmware=$1
TARGET_IP="192.168.0.1"
MAX_RETRIES=60
# =========================================

if [ -z "$firmware" ]; then
    echo "[-] 錯誤: 未提供韌體名稱參數！用法: $0 <firmware_name>"
    exit 1
fi

echo "[+] ======= 啟動原生非 Docker 自動化滲透測試環境 ======="
echo "[+] 選擇韌體標籤: ${firmware}"

# 1. 清理舊的 Python 與 Shell 行程
echo "[+] 1. 清理背景殘留行程..."
pkill -f openfirmware.py 2>/dev/null
pkill -f sentMQTT.py 2>/dev/null
pkill -f startPentest.sh 2>/dev/null
sleep 1

# 2. 自動檢查與修復 FAP 配置路徑
echo "[+] 2. 自動檢查與修復 FAP 配置路徑..."
python3 ./Firmware/modifyToolConfig.py
if [ $? -ne 0 ]; then
    echo "[-] 錯誤: 修復 FAP 配置失敗，腳本終止。"
    exit 1
fi

# 3. 啟動 FAP 初始化韌體（背景執行）
echo "[+] 3. 啟動 FAP 初始化韌體與虛擬網路..."
python3 ./Firmware/openfirmware.py "${firmware}" &

# 4. 🔥 檢查 TARGET_IP (192.168.0.1) 網頁服務是否開啟
echo "[+] 4. 正在監聽 QEMU 靶機網頁服務開機狀態 (http://${TARGET_IP})..."
count=0
while ! curl -s --connect-timeout 2 "http://${TARGET_IP}" > /dev/null; do
    count=$((count + 1))
    if [ $count -ge $MAX_RETRIES ]; then
        echo "[-] 錯誤: 靶機網頁開機逾時 ($MAX_RETRIES 秒)，請確認虛擬機日誌！"
        exit 1
    fi
    echo "[-] 靶機作業系統初始化中，網頁尚未就緒 ($count/$MAX_RETRIES)..."
    sleep 3
done

echo "[+] 🎉 偵測到 http://${TARGET_IP} 網頁服務已成功開啟！靶機 100% 準備就緒！"

# 5. 若需要本地 Mosquitto，確保 MQTT 服務已開啟
if command -v mosquitto > /dev/null 2>&1; then
    echo "[+] 檢測到本地 Mosquitto 服務，嘗試啟動..."
    sudo service mosquitto start 2>/dev/null
fi

# 6. 啟動 Python AI Agent / sentMQTT 腳本
echo "[+] 5. 啟動 Python AI Agent / sentMQTT 腳本..."
python3 ./Firmware/sentMQTT.py "${firmware}" &

# 7. 🔥 網頁開啟完畢後，開啟新 Terminal 視窗執行同目錄下的 startPentest.sh
echo "[+] 6. 網頁已就緒，正在開啟新 Terminal 視窗執行 startPentest.sh..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE}")" && pwd)"
PENTEST_SH="${SCRIPT_DIR}/startPentest.sh"

if [ -n "$DISPLAY" ] || [ -n "$WAYLAND_DISPLAY" ]; then
    if command -v gnome-terminal > /dev/null 2>&1; then
        gnome-terminal --title="Start Pentest - ${firmware}" -- bash -c "bash '${PENTEST_SH}' '${firmware}'; exec bash" &
    elif command -v xterm > /dev/null 2>&1; then
        xterm -title "Start Pentest - ${firmware}" -e "bash -c 'bash \"${PENTEST_SH}\" \"${firmware}\"; exec bash'" &
    elif command -v konsole > /dev/null 2>&1; then
        konsole -p "tabtitle=Start Pentest - ${firmware}" -e "bash -c 'bash \"${PENTEST_SH}\" \"${firmware}\"; exec bash'" &
    else
        echo "[!] 未找到支援的 GUI Terminal，改為背景執行 startPentest.sh"
        bash "${PENTEST_SH}" "${firmware}" &
    fi
else
    echo "[!] 無 GUI 顯示介面環境 (Headless)，改為背景執行 startPentest.sh"
    bash "${PENTEST_SH}" "${firmware}" &
fi

echo "[+] ======= 所有服務與滲透測試 Terminal 已成功開啟！ ======="

# 維持主腳本運作
wait


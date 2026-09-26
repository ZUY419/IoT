#!/bin/bash
# ================= 設定區 =================
firmware=("iot_dir880l_110b01" "dir601_revB_FW_201")
fwnum=1
TARGET_IP="192.168.0.1"
MAX_RETRIES=60
# =========================================

echo "[+] ======= 啟動原生非 Docker 自動化滲透測試環境 ======="

# 1. 清理舊的 Python 行程（避免之前的 FAP 或 Agent 殘留卡住 Port）
echo "[+] 1. 清理背景殘留行程..."
pkill -f openfirmware.py 2>/dev/null
pkill -f sentMQTT.py 2>/dev/null
sleep 1

# 2. 生成與檢查 FAP 配置路徑
echo "[+] 2. 自動檢查與修復 FAP 配置路徑..."
python3 ./Firmware/modifyToolConfig.py
if [ $? -ne 0 ]; then
    echo "[-] 錯誤: 修復 FAP 配置失敗，腳本終止。"
    exit 1
fi

# 3. 啟動 FAP 初始化韌體（丟背景執行）
echo "[+] 3. 啟動 FAP 初始化韌體與虛擬網路..."
python3 ./Firmware/openfirmware.py "${firmware[fwnum]}" &

# 4. 監聽 QEMU 靶機網路服務狀態
echo "[+] 4. 正在監聽 QEMU 靶機虛擬作業系統開機狀態 (HTTP Port 80)..."
count=0
while ! curl -s --connect-timeout 2 "http://${TARGET_IP}" > /dev/null; do
    count=$((count + 1))
    if [ $count -ge $MAX_RETRIES ]; then
        echo "[-] 錯誤: 靶機開機逾時，請確認虛擬機日誌！"
        exit 1
    fi
    echo "[-] 靶機作業系統初始化中，網頁尚未就緒 ($count/$MAX_RETRIES)..."
    sleep 3
done

echo "[+] 🎉 偵測到 ${TARGET_IP} 網頁服務已成功上線！靶機 100% 準備就緒！"
sleep 2

# 5. （可選）若您的 sentMQTT 需用到本地 Mosquitto，確保本地 MQTT 服務已開啟
if command -v mosquitto > /dev/null 2>&1; then
    echo "[+] 檢測到本地 Mosquitto 服務，嘗試啟動..."
    sudo service mosquitto start 2>/dev/null
fi

# 6. 正式啟動 AI Agent 與 MQTT 傳送腳本
echo "[+] 5. 所有基礎建設就緒，啟動 Python AI Agent / sentMQTT 腳本..."
python3 ./Firmware/sentMQTT.py "${firmware[fwnum]}" &

echo "[+] ======= 所有服務已成功原生一鍵啟動！ ======="

# 維持背景腳本持續執行
wait
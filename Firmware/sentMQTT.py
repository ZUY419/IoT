import paho.mqtt.client as mqtt
import time
import subprocess
import os
from pathlib import Path
import sys

# 檢查是否有傳入參數
if len(sys.argv) < 2:
    print("錯誤：請提供韌體名稱作為參數")
    sys.exit(1)

firmware = sys.argv[1]
print(f"sentMQTT 開始處理韌體: {firmware}")

# 設定 Broker 資訊
broker_address = "172.17.0.1" 
topic = "FW_logs"

# 初始化 MQTT Client (使用 VERSION2)
client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)

try:
    client.connect(broker_address, 1883)
    print(f"成功連線至 Broker: {broker_address}")
except Exception as e:
    print(f"無法連線至 MQTT Broker: {e}")
    sys.exit(1)

# 設定路徑
home = os.path.expanduser("~")
# 取得目前檔案所在的目錄
current_dir = Path(__file__).resolve().parent
logs_path = os.path.join(current_dir, "Firmware_logs", f"{firmware}_logs.jsonl")
new_logs_path = os.path.join(current_dir, "Firmware_logs", f"new_{firmware}_logs.jsonl")

print(f"正在監控檔案: {logs_path}")

try:
    while True:
        # 檢查原始 Log 檔案是否存在
        if os.path.exists(logs_path):
            try:
                # 修正 subprocess 語法，將參數放在串列中
                subprocess.run(["mv", logs_path, new_logs_path], check=True)
                
                # 讀取並發送內容
                with open(new_logs_path, "r", encoding="utf-8") as file:
                    for line in file:
                        clean_line = line.strip()
                        if clean_line:  # 確保不是空行
                            client.publish(topic, clean_line)
                
                # 處理完後可以選擇刪除臨時檔，避免下次重複讀取
                os.remove(new_logs_path)
                
            except Exception as e:
                print(f"處理檔案時發生錯誤: {e}")
        else:
            # 檔案不存在時不報錯，安靜地等待（Log 可能還沒產生）
            pass

        time.sleep(5)

except KeyboardInterrupt:
    print("\n程式已手動停止")
finally:
    client.disconnect()
    print("MQTT 已斷開連線")
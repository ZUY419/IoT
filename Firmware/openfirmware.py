import threading
import subprocess
import os
import time
import pty
import webbrowser
import re
import shutil
from pathlib import Path
import json
import sys
import requests

def delete_folder(folder_path):
    if os.path.exists(folder_path):
        try:
            shutil.rmtree(folder_path)
            print(f"[OK] Successfully deleted folder: {folder_path}")
        except Exception as e:
            print(f"[ER] Unsuccessfully deleted folder: {e}")
    else:
        print(f"[WR] Folder does not exist. Skipping deletion: {folder_path}")

def write_to_file(file_path, content, label, firmware):
    """
    以追加模式寫入 JSONL 格式，保護樹莓派 SD 卡
    """
    os.makedirs(os.path.dirname(file_path), exist_ok=True)

    content = f"{content}"

    # 建立單行物件
    entry = {
        "firmware": firmware,
        "timestamp": time.strftime("%H:%M:%S"),
        "label": label,
        "message": content.strip()
    }
    
    # 使用 'a' (append) 模式，直接寫到檔案末尾，不讀取舊資料
    with open(file_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

def info_output(info, firmware):
    # 統一將判斷條件轉大寫，但顯示與儲存保留原始內容
    upper_info = info.upper()
    
    if "WARN" in upper_info:
        print(f"[WR]  {info}")
        write_to_file(f"Firmware_logs/{firmware}_logs.jsonl", info, "Waring", firmware)
        return
    elif "ERROR" in upper_info:
        print(f"[ER] {info}")
        write_to_file(f"Firmware_logs/{firmware}_logs.jsonl", info, "Error", firmware)
        return
    
    if "[+]" in upper_info:
        # 移除前面的 [+] 符號顯示
        display_info = info.replace("[+]", "").strip()
        print(f"[OK] {display_info}")
        write_to_file(f"Firmware_logs/{firmware}_logs.jsonl", info, "Nothing", firmware)
    else:
        print(f"   {info}")
        write_to_file(f"Firmware_logs/{firmware}_logs.jsonl", info, "Nothing", firmware)
    return

def samulating_fw_logic(firmware):
    home = os.path.expanduser("~")
    current_dir = os.path.join(home, Path(__file__).resolve().parent)
    fap_path = "./Firmware_tool/firmware-analysis-plus"

    print(f"[+] Current Path: {current_dir}")
    os.chdir(current_dir)

    enter_sent = False
    url_matched = False
    target_url = None # 初始化
    webIsOpen = False
    match_url = []
    
    # 1. 初始化環境
    print(f"\n[+] Initializing FAP for {firmware}...")
    subprocess.run(f"python3 reset.py", shell=True, cwd=fap_path)
    subprocess.run(f"python3 shutdown.py", shell=True, cwd=fap_path)
    with open(f"Firmware_logs/{firmware}_logs.jsonl", "w", encoding="utf-8") as f:
        f.write("")
    
    # 2. 啟動指令 (使用 -u 確保 stdout 無緩衝)
    fap_cmd = f"stdbuf -oL python3 -u fap.py -q ./qemu-builds/2.5.0/ ./fw_bin/{firmware}.bin"
    print(f"\n[+] Start simulating firmware: {firmware}")
    print("-" * 40)

    # 3. 使用 PTY 啟動
    master, slave = pty.openpty()
    process = subprocess.Popen(
        fap_cmd, 
        shell=True, 
        cwd=fap_path,
        stdin=slave, stdout=slave, stderr=slave,
        text=True, close_fds=True
    )

    os.close(slave)

    try:
        with os.fdopen(master, 'r') as master_file:
            while True:
                line = master_file.readline()
                if not line: break
                
                line = line.strip()
                if not line: continue

                # 顯示與紀錄 Log
                info_output(line, firmware)

                # 偵測網路 IP
                if not url_matched and "NETWORK" in line.upper():
                    matches = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)
                    if matches:
                        for ip in matches:
                            target_url = f"http://{ip}"
                            match_url.append(target_url)
                            print(f"[TR] Target URL ({target_url}) is matched!")
                            write_to_file(f"Firmware_logs/{firmware}_logs.jsonl", target_url, "Network", firmware)
                        url_matched = True

                # 偵測 All set 並按 Enter
                elif "ALL SET" in line.upper() and not enter_sent:
                    time.sleep(2) 
                    os.write(master, b"\n") 
                    print("[OK] Auto-sent Enter key via PTY.")
                    enter_sent = True
                
                # 偵測服務啟動並開啟網頁
                elif not webIsOpen and url_matched:
                    for url in match_url:
                        try:
                            # 建議使用小一點的 timeout，並確認 status_code
                            # 某些韌體即便沒準備好也會回傳非 200 的代碼，可依需求調整
                            response = requests.get(url, timeout=0.5, allow_redirects=True)
                            if response.status_code < 400:
                                print(f"[NK] Web Service Ready! Opening: {url}")
                                webbrowser.open(url)
                                webIsOpen = True
                                break # 成功開啟一個就停止嘗試
                        except requests.RequestException:
                            # 伺服器還沒啟動時會噴 ConnectionError 或 Timeout，直接跳過
                            pass

                if process.poll() is not None:
                    break
    except (OSError, BrokenPipeError):
        pass

    process.wait()
    print("-" * 40)
    print(f"[+] Simulation for {firmware} has finished.")

def main():
    try:
        firmware = f"{sys.argv[1]}"
        print(f"openfirmware get firmware: {firmware}")

        samulating_fw_logic(firmware)

    except ValueError:
        print("Please enter a valid integer.")

if __name__ == "__main__":
    main()
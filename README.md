# AI Agent 模組程式碼與架構說明

本檔案由 `update_readme.py` 自動生成，僅彙整 `AI Agent` 目錄內之核心程式碼。

## 📁 資料夾: `AI Agent/` 

### 📄 `AI Agent/main.py`

```python
# AI Agent/main.py
import sys
import time
import json
import re
import os
from dotenv import load_dotenv

import util
from tools import PentestToolbox
import ai.ollama as ollama
import ai.prompt as prompt
from config.logging import log_info

load_dotenv()

# 從 .env 或 ai.prompt 讀取目標 IP
TARGET_IP = os.getenv("TARGET_IP", prompt.TARGET_IP)

class PentestBox:
    def __init__(self):
        # 初始化設定
        self.turn = 0
        self.current_state = 1
        self.max_steps = 8

        # 初始化共享記憶體：紀錄裝置資訊、歷史紀錄與當前觀測狀態
        self.share_memory = {
            "device_information": {
                "device_type": "IoT Device",
                "target_ip": TARGET_IP
            },
            "history_logs": [],
            "current_observation": prompt.INITIAL_USER_PROMPT
        }

        # 寫入初始 Share Memory 並進行日誌與 JSON 檔案同步
        log_info.share_memory(self.share_memory)

    def parse_json_response(self, raw_text):
        """解析 LLM 回傳的 JSON 決策內容"""
        if not raw_text:
            return None
        try:
            match = re.search(r'\{.*\}', raw_text, re.DOTALL)
            if match:
                return json.loads(match.group(0))
            return json.loads(raw_text)
        except Exception as e:
            log_info.error(f"JSON 解析失敗: {e}")
            return None

    def pentestPipeLine(self):
        log_info.info("🚀 滲透測試 Agent 正式啟動！")

        while True:
            try:
                self.turn += 1
                log_info.info(f"\n>>> 🔄 第 {self.turn} 輪: 當前為第 {self.current_state} 階段 (資產偵察)")

                # 1. 組合 Prompt (System Prompt + 近3輪歷史紀錄 + 當前 Observation)
                full_prompt = f"{prompt.SYSTEM_PROMPT_STAGE_1}\n\n"
                
                history = self.share_memory.get("history_logs", [])
                if history:
                    full_prompt += "【過往執行歷史】:\n"
                    for h in history[-3:]:  # 取最近 3 輪
                        full_prompt += f"- 執行指令: {h['command']}\n  結果: {h['output']}\n"

                full_prompt += f"\n【當前觀測狀態 (Observation)】:\n{self.share_memory['current_observation']}\n"

                # 2. 印出與發送 Prompt 至 Ollama API
                log_info.AI_prompt(full_prompt)
                raw_response = ollama.call_ollama(full_prompt)
                log_info.AI_response(raw_response)

                # 3. 解析 AI 的 JSON 決策
                decision = self.parse_json_response(raw_response)
                if not decision:
                    log_info.warn("無法取得有效 JSON 決策，結束本輪測試。")
                    break

                thought = decision.get("thought", "無說明理由")
                command = decision.get("command", "")
                stage_completed = decision.get("stage_completed", False)

                log_info.info(f"[🧠 思考決策]: {thought}")

                # 4. 判斷階段完成條件或到達輪數上限
                if stage_completed or not command or self.turn >= self.max_steps:
                    log_info.info("🎉 第一階段（資產偵察）宣告完成！")
                    # 同步最新的 share_memory 至檔案中
                    log_info.share_memory(self.share_memory)
                    break

                # 5. 透過 PentestToolbox 執行 CLI 指令
                output = PentestToolbox.execute_cli(command)
                log_info.info(f"[👁️ 觀測結果]: {output[:200]}...")

                # 6. 更新 self.share_memory 狀態並發起持久化同步
                self.share_memory["history_logs"].append({
                    "step": self.turn,
                    "thought": thought,
                    "command": command,
                    "output": output
                })
                self.share_memory["current_observation"] = f"上一輪執行指令 `{command}` 的回傳結果為:\n{output}"

                # 自動同步寫入 data/share memory/share memory.json
                log_info.share_memory(self.share_memory)

                time.sleep(2)

            except KeyboardInterrupt:
                log_info.warn("\n[!] 使用者手動中斷滲透測試，匯出當前記憶體資料中...")
                log_info.share_memory(self.share_memory)
                log_info.info("滲透測試結束")
                break

if __name__ == "__main__":
    pentext = PentestBox()
    pentext.pentestPipeLine()
```

### 📄 `AI Agent/requirements.txt`

```text
python-dotenv
googletrans==4.0.0-rc1
```

### 📄 `AI Agent/tools.py`

```python
import subprocess

import util
from config.logging import log_info

class PentestToolbox:
    def execute_cli(command, timeout=120):
        """執行 Linux CLI 命令並記錄"""
        log_info.tool(command)
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=timeout
            )
            stdout = result.stdout.strip()
            stderr = result.stderr.strip()
            output = stdout if stdout else stderr

            # 長文本截斷，防止過長 Log 塞爆 Context Window
            if len(output) > 1500:
                output = output[:800] + "\n\n...[過長 Log 已自動截斷]...\n\n" + output[-700:]

            return output if output else "（指令執行成功，但無文字輸出）"
        except subprocess.TimeoutExpired:
            log_info.warn(f"指令 `{command}` 執行超過 {timeout} 秒超時")
            return f"（錯誤：指令 `{command}` 執行超過 {timeout} 秒超時）"
        except Exception as e:
            log_info.error(f"執行發生例外狀況: {e}")
            return f"（執行發生例外狀況: {e}）"
```

### 📄 `AI Agent/txt.txt`

```text

```

### 📄 `AI Agent/util.py`

```python
# AI Agent/util.py
import subprocess
import json
import os
from datetime import datetime
from pathlib import Path

from config.logging import log_info

def get_current_folder_path():
    """
    取得目前腳本所在的絕對資料夾路徑
    """
    # 適用於一般 .py 執行檔或腳本
    return Path(os.path.dirname(os.path.abspath(__file__)))

def read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def write_json(path, data):
    """
    安全寫入 JSON 檔案的輔助函式
    """
    try:
        # 確保目標資料夾存在，若不存在則自動建立
        directory = os.path.dirname(path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
            
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
            
        log_info.info(f"資料已成功儲存至: {path}")
        return True
        
    except Exception as e:
        log_info.error(f"[❌ 檔案寫入失敗] 路徑 {path} 寫入異常: {str(e)}")
        return False

folder = get_current_folder_path()
share_memory_file = folder / "data" / "share memory" / "share memory.json"

def updated_share_momery(data):
    log_info.info("Share Memory Updated")
    write_json(share_memory_file, data)

def get_share_memory():
    return read_json(share_memory_file)
```

### 📄 `AI Agent/config/logging.py`

```python
import util

class log_info:
    """
    level = 0(info), 1(warn), 2(error)
    """
    level = 0

    def info(log):
        if log_info.level >= 0:
            print(f"[INFO    ] {log}")

    def tool(tool):
        if log_info.level <= 0:
            print("")
            print(f"[TOOL    ] {tool}")

    def AI_prompt(prompt):
        if log_info.level <= 0:
            print(f"[PROMPT  ] {prompt}")

    def AI_response(response):
        if log_info.level <= 0:
            print(f"[RESPONSE] {response}")

    def warn(log):
        if log_info.level <= 1:
            print(f"[WARN    ] {log}")

    def error(log):
        if log_info.level <= 2:
            print(f"[ERROR   ] {log}")

    def share_memory(data):
        util.updated_share_momery(data)
        if log_info.level <= 2:
            print(f"[SHAREMEM] {data}")
```

### 📄 `AI Agent/ai/ollama.py`

```python
import os
from dotenv import load_dotenv
import requests
import sys
import ai.prompt

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import util

# 1. 載入同目錄下的 .env 檔案
load_dotenv()

# 2. 取得環境變數
OLLAMA_URL = os.getenv("OLLAMA_URL")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")  # 第二個參數為預設值

def call_ollama(prompt):
    payload = {"model": OLLAMA_MODEL, "prompt": prompt, "stream": False}

    response = requests.post(OLLAMA_URL, json=payload).json()
    return response.get("response")
```

### 📄 `AI Agent/ai/prompt.py`

```python
# AI Agent/ai/prompt.py

TARGET_IP = "192.168.0.1"

INITIAL_USER_PROMPT = f"""
滲透測試任務啟動。
目標 IP: {TARGET_IP}
目前狀況：靶機已初始化並成功連通，但尚未進行通訊埠與服務掃描。

請提出第一階段（資產偵察）的執行指令。
"""

SYSTEM_PROMPT_STAGE_1 = f"""
你是一名專業的自動化滲透測試 AI Agent，目前正處於【第一階段：資產偵察與服務列舉 (Reconnaissance)】。

【階段任務】
你的目標是全面收集目標 IP ({TARGET_IP}) 的網路服務資訊。

【嚴格執行規則】
1. 【必須進行 Port 掃描】：在將 "stage_completed" 設為 true 之前，你【必須】至少執行一次 Nmap 通訊埠與服務版本探測（例如使用溫柔掃描參數：`nmap -sS -sV --version-light -T2 192.168.0.1`）。
2. 請勿僅憑 ping 或單一 curl 請求就結束偵察。
3. 命令必須可以在 Ubuntu Linux 中非互動式執行。

【JSON 輸出格式】
你必須且只能輸出嚴格的 JSON 格式：
{{
  "thought": "分析當前情報，說明選擇該命令的理由",
  "command": "準備執行的具體 CLI 指令",
  "stage_completed": false
}}

【階段完成條件】
只有當你透過 Nmap 掃描明確掌握了目標開放的所有埠號與服務版本後，才允許將 "command" 設為 "" 並將 "stage_completed" 設為 true。
"""
```


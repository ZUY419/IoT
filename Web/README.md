更新後的專案程式碼
# AI Agent 模組程式碼與架構說明

本檔案由 `update_readme.py` 自動生成，僅彙整 `AI Agent` 目錄內之核心程式碼。

## 📁 資料夾: `./` 

### 📄 `./index.html`

```
<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>專題網頁展示</title>

    <!-- Google 字體 -->
    <link href="https://fonts.googleapis.com/css2?family=M+PLUS+Rounded+1c:wght@400;700&display=swap" rel="stylesheet">
    <!-- 連結外部 CSS 檔案 -->
    <link rel="stylesheet" href="css/index.css">
</head>
<body>
    <header>
        <section class="web_title">
            <p>專題: 利用 AI Agent 對 IoT 進行滲透測試</p>
        </section>
    </header>

    <!-- 修正：Ubuntu 檔名大小寫敏感，將 JS/index.js 改為小寫 js/index.js -->
    <script src="js/index.js"></script>
    <article>
        <div style="height: 10px;"></div>
        <section class="info_block">
            <!-- 介面按鈕切換區 -->
            <div class="pentest_buttons">
                <section class="switch_show_buttons">
                    <button class="switch_show_button" onclick="switch_button_state(this)" value="IoT Devices">
                        IoT 設備
                    </button>
                    <button class="switch_show_button" onclick="switch_button_state(this)" value="Terminal">
                        終端機
                    </button>
                    <button class="switch_show_button" onclick="switch_button_state(this)" value="Shared Memory">
                        共享記憶體
                    </button>
                    <button class="switch_show_button" onclick="switch_button_state(this)" value="Tool History">
                        工具歷史
                    </button>
                    <button class="switch_show_button" onclick="switch_button_state(this)" value="AI Interaction">
                        AI 互動
                    </button>
                </section>
            </div>
            
            <!-- 介面訊息顯示區 -->
            <section class="info_show">
                <div class="info_title_block">
                    <div class="info_title">
                        <p class="info_title_name"></p>
                        <p class="info_title_data"></p>
                    </div>
                    <p class="pentest_state"></p>
                </div>
                <hr style="margin: 0px; border-color: #FFF8F0;">
                <div class="info_show_block">
                    <!-- 畫面顯示 -->
                </div>
            </section>
        </section>
    </article>
</body>
</html>

```

### 📄 `./test_terminal.py`

```python
import time
import requests

url = "http://localhost:8000/api/pentest/send_log"  # 你的 API 網址

class log_info:
    """
    level = 0(info), 1(warn), 2(error)
    """
    level = 0

    # 內部輔助方法：統一處理 API 發送與例外狀況
    @staticmethod
    def _send(log_content, log_type):
        payload = {
            "log": str(log_content),
            "log_type": log_type
        }
        try:
            # 🚀 實際發送 POST API 請求
            response = requests.post(url, json=payload, timeout=2)
            if response.status_code != 200:
                print(f"[API WARN] 伺服器回應狀態碼: {response.status_code}")
        except requests.exceptions.ConnectionError:
            print(f"[API ERROR] 無法連線到伺服器 ({url})，請確認 FastAPI 是否正在執行。")
        except Exception as e:
            print(f"[API ERROR] 發送日誌失敗: {e}")

    def info(log):
        if log_info.level >= 0:
            print(f"[INFO    ] {log}")
            log_info._send(log, "INFO")

    def tool(tool_name):
        if log_info.level <= 0:
            print("")
            print(f"[TOOL    ] {tool_name}")
            log_info._send(tool_name, "TOOL")

    def warn(log):
        if log_info.level <= 1:
            print(f"[WARN    ] {log}")
            log_info._send(log, "WARN")

    def error(log):
        if log_info.level <= 2:
            print(f"[ERROR   ] {log}")
            log_info._send(log, "ERROR")

    def AI_prompt(prompt):
        if log_info.level <= 0:
            print(f"[PROMPT  ] {prompt}")
            log_info._send(prompt, "AI_PROMPT")

    def AI_response(response):
        if log_info.level <= 0:
            print(f"[RESPONSE] {response}")
            log_info._send(response, "AI_RESPONSE")

# 測試迴圈
while True:
    log_info.info("Start Pentest!")
    log_info.tool("run_nmap_udp")
    log_info.warn("Port Cannot scan!")
    log_info.error("Argument Keyword Error!")
    log_info.AI_prompt("What is Pentest?")
    log_info.AI_response("I don't know what you say.")

    time.sleep(1)
```

### 📄 `./API/main.py`

```python
import json
import os
import shutil
import subprocess
import time
from typing import List, Optional
import urllib.request

from pathlib import Path
from anyio import to_thread
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import API.util as util

app = FastAPI()

# 跨域資源共享 (CORS) 設定
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 全域變數：記錄當前運行的子行程
web_service_process = None
pentest_process = None


# --- WebSocket 連線管理器 ---
class ConnectionManager:

  def __init__(self):
    self.active_connections: List[WebSocket] = []

  async def connect(self, websocket: WebSocket):
    await websocket.accept()
    self.active_connections.append(websocket)
    print(
        "[WebSocket] 新接收端已連線，當前連線數:"
        f" {len(self.active_connections)}"
    )

  def disconnect(self, websocket: WebSocket):
    if websocket in self.active_connections:
      self.active_connections.remove(websocket)
      print(
          "[WebSocket] 接收端已斷開，當前連線數:"
          f" {len(self.active_connections)}"
      )

  async def broadcast(self, message: str):
    disconnected_clients = []
    for connection in self.active_connections:
      try:
        await connection.send_text(message)
      except Exception as e:
        print(f"[WebSocket Error] 發送訊息失敗: {e}")
        disconnected_clients.append(connection)

    for dead_conn in disconnected_clients:
      self.disconnect(dead_conn)


manager = ConnectionManager()


# --- Pydantic Models ---
class CommandPayload(BaseModel):
  log: str
  log_type: str


class StartPentestPayload(BaseModel):
  device_name: Optional[str] = None


# --- 輔助函式：檢查網頁 API 是否就緒 ---
def _check_web_service_ready(url: str, timeout_sec: int = 30) -> bool:
  """輪詢網頁 API，傳回 200 即代表就緒"""
  start_time = time.time()
  while time.time() - start_time < timeout_sec:
    try:
      req = urllib.request.Request(url, headers={"User-Agent": "HealthCheck"})
      with urllib.request.urlopen(req, timeout=2) as response:
        if response.status == 200:
          return True
    except Exception:
      time.sleep(1)
  return False


# --- 輔助函式：構建開啟新 Terminal 的指令 ---
def _build_terminal_command(title: str, script_path: Path, args: List[str] = None) -> List[str]:
  """
  自動偵測系統支援的 Terminal emulator (優先使用 gnome-terminal，其次 xterm)
  並加上可長久維持視窗開著的指令。
  """
  cmd_str = f"bash \"{script_path}\""
  if args:
    cmd_str += " " + " ".join(args)
  
  # 執行完腳本後保持 Terminal 開著 (可觀看 Log 或排錯)
  cmd_str += "; exec bash"

  if shutil.which("gnome-terminal"):
    return ["gnome-terminal", f"--title={title}", "--", "bash", "-c", cmd_str]
  elif shutil.which("xterm"):
    return ["xterm", "-title", title, "-e", "bash", "-c", cmd_str]
  elif shutil.which("konsole"):
    return ["konsole", "-p", f"tabtitle={title}", "-e", "bash", "-c", cmd_str]
  else:
    # 若無桌面 Terminal 模擬器，降級回背景執行
    return ["bash", str(script_path)] + (args if args else [])


# --- 同步任務處理函式 ---
def _sync_get_devices_list():
  """讀取韌體資料夾內的檔案列表"""
  folder = util.get_folder()
  devices_folder = (
      folder.parent.parent
      / "Firmware"
      / "Firmware_tool"
      / "firmware-analysis-plus"
      / "fw_bin"
  ).resolve()

  if not devices_folder.exists() or not devices_folder.is_dir():
    return {"status": 404, "files_name": []}

  file_names = [
      file.name for file in devices_folder.iterdir() if file.is_file()
  ]
  return {"status": 200, "files_name": file_names}


def _sync_start_pentest(device_name: Optional[str]):
  """開獨立 Terminal 執行 run.sh -> 確認網頁正常 -> 開獨立 Terminal 執行 startPentest.sh"""
  global web_service_process, pentest_process

  # 1. 檢查滲透測試是否正在執行
  if pentest_process is not None and pentest_process.poll() is None:
    return {"status": 400, "message": "滲透測試已經在執行中了！"}

  current_folder = util.get_folder()
  project_root = current_folder.parent.parent

  run_sh_path = (project_root / "run.sh").resolve()
  pentest_sh_path = (project_root / "startPentest.sh").resolve()

  if not run_sh_path.exists():
    return {"status": 404, "message": f"找不到 run.sh 腳本: {run_sh_path}"}
  if not pentest_sh_path.exists():
    return {
        "status": 404,
        "message": f"找不到 startPentest.sh 腳本: {pentest_sh_path}",
    }

  env_vars = os.environ.copy()
  # 確保 GUI 視窗能顯示在目前的 X11 / Wayland 顯示器上
  if "DISPLAY" not in env_vars:
    env_vars["DISPLAY"] = ":0"

  # 2. 開啟獨立 Terminal 執行 run.sh
  if web_service_process is None or web_service_process.poll() is not None:
    print("[Pipeline] 正在開啟獨立 Terminal 啟動網頁服務 (run.sh)...")
    run_cmd = _build_terminal_command("IoT Web Service (run.sh)", run_sh_path)
    web_service_process = subprocess.Popen(
        run_cmd, cwd=str(project_root), env=env_vars
    )

  # 3. 檢查網頁服務狀態 (健康檢查)
  target_health_url = "http://192.168.0.1"
  print(f"[Pipeline] 等待網頁服務就緒 ({target_health_url})...")
  is_ready = _check_web_service_ready(target_health_url, timeout_sec=25)

  if not is_ready:
    return {
        "status": 500,
        "message": "網頁服務 (run.sh) 啟動超時，取消啟動滲透測試視窗。",
    }

  print("[Pipeline] 網頁服務運作正常！開啟獨立 Terminal 執行滲透測試 (startPentest.sh)...")

  # 4. 開啟獨立 Terminal 執行 startPentest.sh
  pentest_args = ["--device", device_name] if device_name else []
  pentest_cmd = _build_terminal_command("IoT Start Pentest", pentest_sh_path, pentest_args)

  try:
    pentest_process = subprocess.Popen(
        pentest_cmd, cwd=str(project_root), env=env_vars
    )

    return {
        "status": 200,
        "message": "已成功開啟獨立 Terminal 視窗執行網頁與滲透測試服務！",
        "web_pid": web_service_process.pid,
        "pentest_pid": pentest_process.pid,
    }
  except Exception as e:
    return {"status": 500, "message": f"開啟 Terminal 視窗失敗: {str(e)}"}


# --- API 端點 ---


@app.post("/api/pentest/send_log")
async def receive_from_a(payload: CommandPayload):
  log_data = json.dumps({"log": payload.log, "log_type": payload.log_type})
  await manager.broadcast(log_data)
  return {"status": 200, "message": "Log 已成功廣播"}


@app.websocket("/ws/receive_b")
async def websocket_b(websocket: WebSocket):
  await manager.connect(websocket)
  try:
    while True:
      await websocket.receive_text()
  except WebSocketDisconnect:
    manager.disconnect(websocket)
  except Exception as e:
    manager.disconnect(websocket)


@app.post("/api/pentest/get_devices_list")
async def get_devices_list():
  try:
    return await to_thread.run_sync(_sync_get_devices_list)
  except Exception as e:
    return {"status": 500, "files_name": [], "error": str(e)}


@app.post("/api/pentest/start_pentest")
async def start_pentest(payload: StartPentestPayload = None):
  try:
    device_name = payload.device_name if payload else None
    return await to_thread.run_sync(_sync_start_pentest, device_name)
  except Exception as e:
    return {"status": 500, "message": str(e)}
```

### 📄 `./API/util.py`

```python
from pathlib import Path

def get_folder():
    return Path(__file__).resolve().parent
```

### 📄 `./css/index.css`

```
/* 全局重置 */
* {
    box-sizing: border-box;
}

p, span, button {
    font-family: "M PLUS Rounded 1c", "Fira Code", Arial, sans-serif;
    padding: 0;
    margin: 0;
}

body {
    width: 100vw;
    height: 100vh;
    margin: 0;
    padding: 12px;
    display: flex;
    flex-direction: column;
    gap: 12px;
    background-color: #FFF8F0;
    overflow: hidden;
}

/* 頁首 Header */
header {
    height: 60px;
    width: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    background-color: #4B2E2B;
    border-radius: 16px;
    box-shadow: 0 4px 12px rgba(140, 90, 60, 0.3);
    flex-shrink: 0;
}

.web_title {
    color: #C08552;
    font-size: 30px;
    font-weight: bold;
}

article {
    flex: 1;
    display: flex;
    min-height: 0;
}

.info_block {
    width: 100%;
    height: 100%;
    border-radius: 16px;
    background-color: #4B2E2B;
    box-shadow: 0 6px 16px rgba(140, 90, 60, 0.35);
    display: flex;
    flex-direction: column;
    padding: 12px;
    gap: 10px;
}

/* 分頁切換按鈕區 */
.switch_show_buttons {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 4px 0;
    flex-shrink: 0;
}

.switch_show_button {
    height: 42px;
    padding: 0 20px;
    border-radius: 12px;
    border: none;
    background-color: transparent;
    color: #C08552;
    font-size: 20px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.25s ease;
}

.switch_show_button:hover {
    background-color: rgba(140, 90, 60, 0.4);
    color: #FFF8F0;
}

.switch_show_button.action {
    background-color: #8C5A3C;
    color: #FFF8F0;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
}

/* 內容顯示主要區塊 */
.info_show {
    flex: 1;
    min-height: 0;
    padding: 12px;
    background-color: #120a09;
    border: 2px solid #C08552;
    border-radius: 14px;
    display: flex;
    flex-direction: column;
    gap: 5px;
    box-shadow: inset 0 0 20px rgba(0, 0, 0, 0.8);
}

.info_title_block {
    flex-shrink: 0;
    display: flex;
    flex-direction: row;
    align-items: baseline;
    justify-content: space-between;
}

.info_title {
    display: flex;
    align-items: baseline;
    gap: 12px;
}

.info_title_name {
    font-size: 26px;
    font-weight: bold;
    color: #FFF8F0;
}

.info_title_data {
    font-size: 16px;
    font-weight: bold;
    color: #FFF8F0;
}

.info_show_block {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
}

/* 終端顯示主區塊 */
.terminal_show_block {
    height: 100%;
    width: 100%;
    
    background-color: transparent;
    
    font-family: 'Fira Code', 'Consolas', 'Courier New', monospace;
    font-size: 13.5px;
    font-weight: bold;

    line-height: 1.6;
    
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 6px;
}

/* 深色美化滾動條 */
.terminal_show_block::-webkit-scrollbar,
.info_show_block::-webkit-scrollbar {
    width: 6px;
}
.terminal_show_block::-webkit-scrollbar-track,
.info_show_block::-webkit-scrollbar-track {
    background: rgba(255, 255, 255, 0.03);
}
.terminal_show_block::-webkit-scrollbar-thumb,
.info_show_block::-webkit-scrollbar-thumb {
    background-color: #8C5A3C;
    border-radius: 3px;
}

/* Log 每列通用設定 */
div[class$="_section"] {
    display: flex;
    align-items: center;
    gap: 12px;
    width: 100%;
    word-break: break-all;
}

[class^="log_type_"] {
    font-weight: 700;
    font-size: 12px;
    padding: 3px 10px;
    border-radius: 5px;
    letter-spacing: 0.6px;
    text-transform: uppercase;
    min-width: 110px;
    text-align: center;
    user-select: none;
    flex-shrink: 0;
}

/* Log 配色 */
.log_type_INFO { background-color: rgba(56, 189, 248, 0.12); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.35); }
.log_content_INFO { color: #e2e8f0; }

.log_type_TOOL { background-color: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.4); }
.log_content_TOOL { color: #f3e8ff; font-weight: 600; }

.log_type_WARN { background-color: rgba(251, 191, 36, 0.15); color: #fbbf24; border: 1px solid rgba(251, 191, 36, 0.4); }
.log_content_WARN { color: #fef08a; }

.log_type_ERROR { background-color: rgba(248, 113, 113, 0.15); color: #f87171; border: 1px solid rgba(248, 113, 113, 0.4); }
.log_content_ERROR { color: #fecaca; font-weight: 600; }

.log_type_AI_PROMPT { background-color: rgba(52, 211, 153, 0.15); color: #34d399; border: 1px solid rgba(52, 211, 153, 0.4); }
.log_content_AI_PROMPT { color: #a7f3d0; }

.log_type_AI_RESPONSE { background-color: rgba(244, 114, 182, 0.15); color: #f472b6; border: 1px solid rgba(244, 114, 182, 0.4); }
.log_content_AI_RESPONSE { color: #fbcfe8; }

/* 設備選擇區域 */
.device_selection_block {
    margin: 8px 0;
    padding: 10px 16px;
    background-color: #FFF8F0;
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: space-between;
}
.device_name { color: #8C5A3C; font-size: 20px; font-weight: bold; }
.device_button { color: #2A835F; font-size: 16px; font-weight: bold; background: transparent; border: none; cursor: pointer; }
.device_button:hover { color: #092328; }

/* ==========================================
   Tool Card 工具卡片設計
   ========================================== */
.tool_card {
    background-color: #1a1010;
    border: 1px solid rgba(168, 85, 247, 0.4); /* 科技紫邊框 */
    border-radius: 10px;
    margin-bottom: 14px;
    padding: 12px 14px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
    transition: transform 0.2s ease, border-color 0.2s ease;
}

.tool_card:hover {
    border-color: rgba(192, 132, 252, 0.8);
    transform: translateY(-2px);
}

/* 卡片頁首 */
.tool_card_header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding-bottom: 8px;
    border-bottom: 1px dashed rgba(255, 255, 255, 0.1);
    margin-bottom: 10px;
}

.tool_title_group {
    display: flex;
    align-items: center;
    gap: 10px;
}

/* TOOL Badge 標籤 */
.tool_badge {
    background-color: rgba(168, 85, 247, 0.2);
    color: #c084fc;
    border: 1px solid rgba(168, 85, 247, 0.5);
    font-size: 11px;
    font-weight: bold;
    padding: 2px 8px;
    border-radius: 4px;
    letter-spacing: 0.5px;
}

/* 工具名稱 */
.tool_name {
    color: #FFF8F0;
    font-size: 16px;
    font-weight: bold;
    font-family: 'Fira Code', monospace;
}

/* 狀態顯示 */
.tool_status {
    color: #34d399; /* 翡翠綠表示執行完成 */
    font-size: 11px;
    font-weight: bold;
    letter-spacing: 0.5px;
}

/* 卡片內容區域 */
.tool_card_body {
    display: flex;
    flex-direction: column;
    gap: 8px;
}

.tool_field {
    display: flex;
    flex-direction: column;
    gap: 4px;
}

.tool_label {
    color: #C08552;
    font-size: 12px;
    font-weight: bold;
    font-family: 'Fira Code', monospace;
}

/* 參數與回應的黑客終端框 (<pre>) */
.tool_argument,
.tool_response {
    background-color: #0d0807;
    border: 1px solid #302020;
    border-radius: 6px;
    padding: 8px 10px;
    margin: 0;
    font-family: 'Fira Code', 'Consolas', monospace;
    font-size: 13px;
    line-height: 1.4;
    white-space: pre-wrap;  /* 自動換行 */
    word-break: break-all;
    max-height: 150px;       /* 超過高度出現滾動條 */
    overflow-y: auto;
}

/* 參數點亮顏色 */
.tool_argument {
    color: #fef08a; /* 軟黃色高亮參數 */
}

/* 回應點亮顏色 */
.tool_response {
    color: #e2e8f0; /* 純淨灰白 */
}

/* 美化滾動條 */
.tool_argument::-webkit-scrollbar,
.tool_response::-webkit-scrollbar {
    width: 4px;
}
.tool_argument::-webkit-scrollbar-thumb,
.tool_response::-webkit-scrollbar-thumb {
    background-color: #8C5A3C;
    border-radius: 2px;
}

/* AI 互動容器與對話卡片樣式 */
.ai_show_block {
    height: 100%;
    width: 100%;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 12px;
    padding-right: 6px;
}

.ai_show_block::-webkit-scrollbar {
    width: 6px;
}
.ai_show_block::-webkit-scrollbar-thumb {
    background-color: #8C5A3C;
    border-radius: 3px;
}

.ai_message_card {
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding: 10px 14px;
    border-radius: 10px;
    max-width: 85%;
    font-family: 'Fira Code', 'M PLUS Rounded 1c', monospace;
    font-size: 14px;
    line-height: 1.5;
    word-break: break-all;
    white-space: pre-wrap;
    box-shadow: 0 3px 8px rgba(0, 0, 0, 0.3);
}

.ai_msg_header {
    font-size: 11px;
    font-weight: bold;
    letter-spacing: 0.8px;
    opacity: 0.8;
}

.ai_msg_prompt {
    align-self: flex-start;
    background-color: rgba(52, 211, 153, 0.1);
    border: 1px solid rgba(52, 211, 153, 0.4);
    color: #a7f3d0;
}
.ai_msg_prompt .ai_msg_header {
    color: #34d399;
}

.ai_msg_response {
    align-self: flex-end;
    background-color: rgba(244, 114, 182, 0.1);
    border: 1px solid rgba(244, 114, 182, 0.4);
    color: #fbcfe8;
}
.ai_msg_response .ai_msg_header {
    color: #f472b6;
}
```

### 📄 `./js/index.js`

```
// 記錄目前正在執行的設備名稱與分頁狀態
var started_device = "";
var current_tab = "";
var log_history = ""; // 專門保存 Terminal 歷史 Log (不含 AI)
var ai_history = "";  // 專門保存 AI 互動歷史 Log

const HOSTNAME = window.location.hostname || "localhost";
const API_BASE_URL = `http://${HOSTNAME}:8000`;
const WS_BASE_URL = `ws://${HOSTNAME}:8000`;

// 分頁切換
async function switch_button_state(clickedButton) {
    const buttonValue = clickedButton.value;
    current_tab = buttonValue;

    const AllButton = document.querySelectorAll(".switch_show_button");
    AllButton.forEach(btn => {
        if (btn !== clickedButton) {
            btn.classList.remove("action");
            btn.style.fontSize = "";
        } else {
            btn.classList.add("action");
            btn.style.fontSize = "22px";
        }
    });

    const info_show_block = document.querySelector(".info_show_block");
    const info_title_name = document.querySelector(".info_title_name");
    const info_title_data = document.querySelector(".info_title_data");
    const pentest_state = document.querySelector(".pentest_state");

    info_show_block.innerHTML = "";
    info_title_name.textContent = "";
    info_title_data.textContent = "";
    pentest_state.textContent = "";

    if (buttonValue === "Shared Memory") {
        info_title_name.textContent = "當前共享記憶體的資料";
        info_show_block.innerHTML = `<p style="color: #FFF8F0;">共享記憶體內容...</p>`;

    } else if (buttonValue === "Tool History") {
        info_title_name.textContent = "當前使用過的工具";
        info_show_block.innerHTML = `<p style="color: #FFF8F0;">工具歷史紀錄...</p>`;

    } else if (buttonValue === "AI Interaction") {
        // 🤖 切換至 AI 互動分頁
        info_title_name.textContent = "與 AI 的對話紀錄";
        info_show_block.innerHTML = `<div class="ai_show_block" id="ai_container">${ai_history}</div>`;
        scrollToBottom("ai_container");

    } else if (buttonValue === "Terminal") {
        // 🖥️ 切換至 Terminal 分頁
        info_title_name.textContent = "當前工具 Terminal Log";
        info_show_block.innerHTML = `<div class="terminal_show_block" id="terminal_container">${log_history}</div>`;
        scrollToBottom("terminal_container");

    } else if (buttonValue === "IoT Devices") {
        info_title_name.textContent = "當前設備:";
        info_title_data.textContent = started_device !== "" ? started_device : "尚未選擇設備";

        const devices_name = await get_devices_name();
        if (devices_name && devices_name.length > 0) {
            let devicesHTML = "";
            devices_name.forEach(file_name => {
                const isStarted = (file_name === started_device);
                const btnText = isStarted ? "Started" : "Start";
                const btnColor = isStarted ? "color: #092328;" : "";

                devicesHTML += `
                    <div class="device_selection_block" id="dev_${file_name}">
                        <p class="device_name">${file_name}</p>
                        <button class="device_button" id="${file_name}" style="${btnColor}" onclick="start_device(this)">${btnText}</button>
                    </div>
                `;
            });
            info_show_block.innerHTML = devicesHTML;
        } else {
            info_show_block.innerHTML = `<p class="device_name" style="color: #f87171;">找不到任何 IoT 設備檔案</p>`;
        }
    }
}

// 啟動設備測試
async function start_device(clickedButton) {
    const deviceName = clickedButton.id;

    if (started_device === "") {
        clickedButton.textContent = "Started";
        clickedButton.style.color = "#092328";

        started_device = deviceName;

        const info_title_data = document.querySelector(".info_title_data");
        if (info_title_data) info_title_data.textContent = deviceName;
        
        initReceiver();
        await start_pentest(deviceName);
    } else if (started_device !== deviceName) {
        alert(`目前已有設備 [${started_device}] 正在執行中，請先停止它！`);
    }
}

let wsB = null;

// 通用自動滾動到底部
function scrollToBottom(containerId) {
    const container = document.getElementById(containerId);
    if (container) {
        container.scrollTop = container.scrollHeight;
    }
}

// 初始化並連線 WebSocket
function initReceiver() {
    if (wsB && wsB.readyState === WebSocket.OPEN) return;

    wsB = new WebSocket(`${WS_BASE_URL}/ws/receive_b`);

    wsB.onopen = function() {
        console.log("[WebSocket] 成功連線至即時日誌接收通道");
    };

    wsB.onmessage = function(event) {
        const data = JSON.parse(event.data);

        // 🔀 完全分離條件判斷
        if (data.log_type === "AI_PROMPT" || data.log_type === "AI_RESPONSE") {
            // ================= 1. AI 專用 Log =================
            const isPrompt = data.log_type === "AI_PROMPT";
            const roleClass = isPrompt ? "ai_msg_prompt" : "ai_msg_response";
            const roleLabel = isPrompt ? "PROMPT / Prompt" : "AI RESPONSE";

            const newAiHTML = `
                <div class="ai_message_card ${roleClass}">
                    <div class="ai_msg_header">${roleLabel}</div>
                    <div class="ai_msg_body">${escapeHtml(data.log)}</div>
                </div>
            `;
            ai_history += newAiHTML;

            // 若當前在 AI Interaction 分頁，即時渲染
            if (current_tab === "AI Interaction") {
                const aiContainer = document.getElementById("ai_container");
                if (aiContainer) {
                    aiContainer.insertAdjacentHTML('beforeend', newAiHTML);
                    scrollToBottom("ai_container");
                }
            }

        } else {
            // ================= 2. Terminal 工具 Log (非 AI) =================
            const newTerminalLogHTML = `
                <div class="log_${data.log_type}_section">
                    <span class="log_type_${data.log_type}">${data.log_type}</span> 
                    <span class="log_content_${data.log_type}">${escapeHtml(data.log)}</span>
                </div>
            `;
            log_history += newTerminalLogHTML;

            // 若當前在 Terminal 分頁，即時渲染
            if (current_tab === "Terminal") {
                const termContainer = document.getElementById("terminal_container");
                if (termContainer) {
                    termContainer.insertAdjacentHTML('beforeend', newTerminalLogHTML);
                    scrollToBottom("terminal_container");
                }
            }
        }
    };

    wsB.onclose = function() {
        console.warn("[WebSocket] 連線已斷開，3 秒後嘗試自動重連...");
        setTimeout(() => {
            if (started_device !== "") initReceiver();
        }, 3000);
    };

    wsB.onerror = function(err) {
        console.error("[WebSocket Exception]", err);
    };
}

// 安全字元轉換 (避免 XSS 注入)
function escapeHtml(text) {
    return String(text)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// 取得裝置清單 API
async function get_devices_name() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/pentest/get_devices_list`, {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });

        if (response.ok) {
            const data = await response.json();
            return data.files_name;
        } else {
            return [];
        }
    } catch (error) {
        return [];
    }
}

// 發送 start_pentest API
async function start_pentest(deviceName) {
    try {
        const response = await fetch(`${API_BASE_URL}/api/pentest/start_pentest`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ device_name: deviceName })
        });

        if (response.ok) {
            console.log(`[Pentest] 成功啟動裝置 [${deviceName}]！`);
        } else {
            const errData = await response.json();
            alert(`啟動失敗: ${errData.message || response.statusText}`);
        }
    } catch (error) {
        console.error("無法啟動測試:", error);
    }
}

// 頁面初始化
window.addEventListener("DOMContentLoaded", () => {
    pentest_button_init();
});

function pentest_button_init() {
    const firstButton = document.querySelector(".switch_show_button");
    if (firstButton) {
        switch_button_state(firstButton);
    }
}
```


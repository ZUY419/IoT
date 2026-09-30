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
    <title>AI Agent IoT 滲透測試控制台</title>

    <!-- Google 字體與 Fira Code 程式碼字型 -->
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;600;700&family=M+PLUS+Rounded+1c:wght@400;700&display=swap" rel="stylesheet">
    <!-- 外部樣式表 -->
    <link rel="stylesheet" href="css/index.css">
</head>
<body>
    <header>
        <section class="web_title">
            <p>專題: 利用 AI Agent 對 IoT 進行滲透測試</p>
        </section>
    </header>

    <!-- 腳本引入 (注意 Linux 下小寫路徑) -->
    <script src="js/index.js"></script>

    <article>
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
                <hr style="margin: 0px; border-color: #C08552; opacity: 0.4;">
                <div class="info_show_block">
                    <!-- 動態內容渲染區 -->
                </div>
            </section>
        </section>
    </article>
</body>
</html>

```

### 📄 `./API/main.py`

```python
import json
import os
import shutil
import subprocess
import time
import urllib.request
import threading
import sys

from typing import List, Optional
from pathlib import Path
from anyio import to_thread
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import API.util as util

app = FastAPI()

# 設定 CORS 允許跨域連線
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

web_service_process = None
pentest_process = None

class ConnectionManager:

  def __init__(self):
    self.active_connections: List[WebSocket] = []

  async def connect(self, websocket: WebSocket):
    await websocket.accept()
    self.active_connections.append(websocket)
    print(
        f"[WebSocket] 新接收端已連線，當前連線數: {len(self.active_connections)}"
    )

  def disconnect(self, websocket: WebSocket):
    if websocket in self.active_connections:
      self.active_connections.remove(websocket)
      print(
          f"[WebSocket] 接收端已斷開，當前連線數: {len(self.active_connections)}"
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

class CommandPayload(BaseModel):
  log: str
  log_type: str

class StartPentestPayload(BaseModel):
  device_name: Optional[str] = None

def _check_web_service_ready(url: str, timeout_sec: int = 30) -> bool:
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

def _build_terminal_command(
    title: str, script_path: Path, args: List[str] = None
) -> List[str]:
  cmd_str = f'bash "{script_path}"'
  if args:
    cmd_str += " " + " ".join(args)
  cmd_str += "; exec bash"

  has_display = (
      os.environ.get("DISPLAY") is not None
      or os.environ.get("WAYLAND_DISPLAY") is not None
  )

  if has_display and shutil.which("gnome-terminal"):
    return ["gnome-terminal", f"--title={title}", "--", "bash", "-c", cmd_str]
  elif has_display and shutil.which("xterm"):
    return ["xterm", "-title", title, "-e", "bash", "-c", cmd_str]
  elif has_display and shutil.which("konsole"):
    return ["konsole", "-p", f"tabtitle={title}", "-e", "bash", "-c", cmd_str]
  else:
    # 無 GUI 視窗環境下自動降級為背景執行
    return ["bash", str(script_path)] + (args if args else [])

def _sync_get_devices_list():
  folder = util.get_folder()
  devices_folder = (
      folder.parent.parent
      / "Firmware"
      / "Firmware_tool"
      / "firmware-analysis-plus"
      / "fw_bin"
  ).resolve()

  if not devices_folder.exists() or not devices_folder.is_dir():
    print(f"[!] 找不到韌體資料夾: {devices_folder}")
    return {"status": 404, "files_name": []}

  file_names = [
      file.stem for file in devices_folder.iterdir() if file.is_file()
  ]
  return {"status": 200, "files_name": file_names}

def _sync_start_pentest(device_name: Optional[str]):
    global web_service_process

    if web_service_process is not None and web_service_process.poll() is None:
        return {"status": 400, "message": "滲透測試服務已經在執行中了！"}

    current_folder = util.get_folder()
    project_root = current_folder.parent.parent

    run_sh_path = (project_root / "run.sh").resolve()

    if not run_sh_path.exists():
        return {"status": 404, "message": f"找不到 run.sh 腳本: {run_sh_path}"}

    env_vars = os.environ.copy()
    if "DISPLAY" not in env_vars:
        env_vars["DISPLAY"] = ":0"

    try:
        run_args = [device_name] if device_name else []
        run_cmd = _build_terminal_command("IoT Pentest Master (run.sh)", run_sh_path, run_args)
        
        web_service_process = subprocess.Popen(
            run_cmd, cwd=str(project_root), env=env_vars
        )

        return {
            "status": 200,
            "message": f"已成功啟動滲透測試環境，將於網頁就緒後自動開啟 startPentest.sh 視窗！",
            "pid": web_service_process.pid
        }
    except Exception as e:
        return {"status": 500, "message": f"啟動失敗: {str(e)}"}

# ===== 重啟 Uvicorn 的輔助函式 =====
# def _restart_uvicorn():
#     """延遲重啟 Uvicorn 服務（以相同參數重新執行當前 Python 行程）"""
#     print("[*] 正在關閉並重新開啟 Uvicorn 服務...")
#     os.execv(sys.executable, [sys.executable] + sys.argv)

# ===== 修改後的停止與重啟函式 =====
def _sync_stop_pentest():
    global web_service_process, pentest_process

    # 1. 先安全關閉 Python 記錄的腳本行程
    if pentest_process is not None and pentest_process.poll() is None:
        try:
            pentest_process.terminate()
            pentest_process.wait(timeout=2)
        except Exception:
            pentest_process.kill()
        pentest_process = None

    if web_service_process is not None and web_service_process.poll() is None:
        try:
            web_service_process.terminate()
            web_service_process.wait(timeout=2)
        except Exception:
            web_service_process.kill()
        web_service_process = None

    # 2. 強制關閉系統中所有正在執行的 .sh 腳本（含 run.sh, startPentest.sh 及其子行程）
    try:
        subprocess.run(["pkill", "-9", "-f", r"\.sh"], check=False)
        subprocess.run(["pkill", "-9", "-f", "run.sh"], check=False)
        subprocess.run(["pkill", "-9", "-f", "startPentest.sh"], check=False)
        print("[*] 已發送 pkill 強制清理所有 .sh 行程")
    except Exception as e:
        print(f"[!] 清除 .sh 行程時發生例外: {e}")

    # 3. 安排 1 秒後觸發 Uvicorn 重啟 (留時間讓 API 完成 HTTP 200 回應)
    # threading.Timer(1.0, _restart_uvicorn).start()

    return {
        "status": 200,
        "message": "已成功關閉所有 .sh 腳本，Uvicorn 服務將於 1 秒內自動重啟！"
    }

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
  except Exception:
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

@app.post("/api/pentest/stop_pentest")
async def stop_pentest():
  try:
    return await to_thread.run_sync(_sync_stop_pentest)
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
    font-size: 28px;
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

/* 內容顯示主區域 */
.info_show {
    flex: 1;
    min-height: 0;
    padding: 12px;
    background-color: #120a09;
    border: 2px solid #C08552;
    border-radius: 14px;
    display: flex;
    flex-direction: column;
    gap: 8px;
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
    font-size: 24px;
    font-weight: bold;
    color: #FFF8F0;
}

.info_title_data {
    font-size: 16px;
    font-weight: bold;
    color: #C08552;
}

.info_show_block {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
}

/* 深色美化滾動條 */
.terminal_show_block::-webkit-scrollbar,
.info_show_block::-webkit-scrollbar,
.ai_show_block::-webkit-scrollbar,
.memory_dashboard::-webkit-scrollbar {
    width: 6px;
}
.terminal_show_block::-webkit-scrollbar-track,
.info_show_block::-webkit-scrollbar-track,
.ai_show_block::-webkit-scrollbar-track,
.memory_dashboard::-webkit-scrollbar-track {
    background: rgba(255, 255, 255, 0.03);
}
.terminal_show_block::-webkit-scrollbar-thumb,
.info_show_block::-webkit-scrollbar-thumb,
.ai_show_block::-webkit-scrollbar-thumb,
.memory_dashboard::-webkit-scrollbar-thumb {
    background-color: #8C5A3C;
    border-radius: 3px;
}

/* 終端 Terminal 樣式 */
.terminal_show_block {
    height: 100%;
    width: 100%;
    background-color: transparent;
    font-family: 'Fira Code', 'Consolas', monospace;
    font-size: 13.5px;
    font-weight: bold;
    line-height: 1.6;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 6px;
}

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

/* IoT 設備選擇區域與按鈕組 */
.device_selection_block {
    margin: 8px 0;
    padding: 10px 16px;
    background-color: #FFF8F0;
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: space-between;
}

.device_name { 
    color: #8C5A3C; 
    font-size: 20px; 
    font-weight: bold; 
}

.device_btn_group {
    display: flex;
    gap: 10px;
    align-items: center;
}

.device_button { 
    padding: 6px 16px; 
    font-size: 15px; 
    font-weight: bold; 
    border-radius: 8px; 
    cursor: pointer; 
    border: none; 
    transition: all 0.25s ease;
}

.device_button.start_btn { 
    background-color: #2A835F; 
    color: #FFF8F0; 
}

.device_button.start_btn:hover:not(:disabled) { 
    background-color: #1e5e44; 
}

.device_button.start_btn.active { 
    background-color: #164f38; 
    color: #A7F3D0; 
}

.device_button.stop_btn { 
    background-color: #B91C1C; 
    color: #FFF8F0; 
}

.device_button.stop_btn:hover:not(:disabled) { 
    background-color: #991B1B; 
}

.device_button:disabled { 
    background-color: #6B7280; 
    color: #D1D5DB; 
    cursor: not-allowed; 
    opacity: 0.6; 
}

/* Tool History 工具卡片 */
.tool_card {
    background-color: #1a1010;
    border: 1px solid rgba(168, 85, 247, 0.4);
    border-radius: 10px;
    margin-bottom: 12px;
    padding: 12px 14px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
}

.tool_card_header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding-bottom: 8px;
    border-bottom: 1px dashed rgba(255, 255, 255, 0.1);
    margin-bottom: 8px;
}

.tool_badge {
    background-color: rgba(168, 85, 247, 0.2);
    color: #c084fc;
    border: 1px solid rgba(168, 85, 247, 0.5);
    font-size: 11px;
    font-weight: bold;
    padding: 2px 8px;
    border-radius: 4px;
}

.tool_name {
    color: #FFF8F0;
    font-size: 15px;
    font-weight: bold;
    font-family: 'Fira Code', monospace;
}

.tool_argument {
    background-color: #0d0807;
    border: 1px solid #302020;
    color: #fef08a;
    border-radius: 6px;
    padding: 8px 10px;
    font-family: 'Fira Code', monospace;
    font-size: 13px;
    white-space: pre-wrap;
    word-break: break-all;
}

/* AI 對話卡片 */
.ai_show_block {
    height: 100%;
    width: 100%;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 12px;
    padding-right: 4px;
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
.ai_msg_prompt .ai_msg_header { color: #34d399; }

.ai_msg_response {
    align-self: flex-end;
    background-color: rgba(244, 114, 182, 0.1);
    border: 1px solid rgba(244, 114, 182, 0.4);
    color: #fbcfe8;
}
.ai_msg_response .ai_msg_header { color: #f472b6; }

/* 通用型共享記憶體 (Shared Memory) 面板 */
.memory_dashboard {
    display: flex;
    flex-direction: column;
    gap: 14px;
    height: 100%;
    overflow-y: auto;
    padding-right: 4px;
    font-family: 'Fira Code', 'Consolas', monospace;
}

.mem_card {
    background-color: #1a1010;
    border: 1px solid #C08552;
    border-radius: 10px;
    padding: 12px 14px;
    box-shadow: 0 4px 10px rgba(0, 0, 0, 0.35);
}

.mem_card_title {
    font-size: 15px;
    font-weight: bold;
    color: #FFF8F0;
    margin-bottom: 10px;
    border-bottom: 1px dashed rgba(192, 133, 82, 0.4);
    padding-bottom: 5px;
}

.mem_info_grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(210px, 1fr));
    gap: 10px;
}

.mem_info_item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    background-color: #0d0807;
    padding: 6px 10px;
    border-radius: 6px;
    border: 1px solid #302020;
}

.mem_label { color: #C08552; font-size: 12.5px; font-weight: bold; }
.mem_val { color: #FFF8F0; font-size: 13px; font-weight: bold; word-break: break-all; }

/* 數據表格 */
.table_responsive {
    width: 100%;
    overflow-x: auto;
    border-radius: 6px;
    border: 1px solid #302020;
}

.mem_table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12.5px;
    background-color: #0d0807;
    text-align: left;
}

.mem_table th {
    background-color: #2a1817;
    color: #C08552;
    padding: 8px 10px;
    font-weight: bold;
    border-bottom: 1px solid #302020;
    white-space: nowrap;
}

.mem_table td {
    padding: 8px 10px;
    color: #e2e8f0;
    border-bottom: 1px solid #1a1010;
}

.generic_array_group {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
}

.array_tag_item {
    background-color: #2a1817;
    color: #fef08a;
    border: 1px solid #8C5A3C;
    padding: 3px 8px;
    border-radius: 5px;
    font-size: 12px;
}

.val_null { color: #64748b; font-style: italic; }
.val_empty { color: #64748b; font-size: 12px; padding: 2px 0; }
.val_primitive { color: #a7f3d0; }

.raw_json_details {
    color: #C08552;
    cursor: pointer;
    font-size: 13px;
    margin-top: 6px;
}

.raw_json_details summary {
    padding: 4px 0;
    font-weight: bold;
}

.memory_empty_notice {
    color: #FFF8F0;
    text-align: center;
    padding: 40px;
    font-size: 16px;
    opacity: 0.7;
}

```

### 📄 `./js/index.js`

```
"use strict";

// ===== 全域狀態管理 =====
const state = {
    started_device: "",
    current_tab: "",
    current_tool: "",
    log_history: "",
    ai_history: "",
    share_memory_data: null,
    tool_history_logs: []
};

// 效能設定
const CONFIG = {
    MAX_LOG_ENTRIES: 300, // Terminal / AI 訊息最大保留數，防止 DOM 爆炸
    RECONNECT_INTERVAL: 3000 // WebSocket 重連間隔 (ms)
};

let wsB = null;
let reconnectTimer = null;

// 動態伺服器位址設定 (自動匹配 Host，避免硬編碼 localhost)
const HOSTNAME = window.location.hostname || "localhost";
const API_BASE_URL = `http://${HOSTNAME}:8000`;
const WS_BASE_URL = `ws://${HOSTNAME}:8000`;

// ===== 1. 分頁切換與 UI 渲染 =====
async function switch_button_state(clickedButton) {
    if (!clickedButton) return;

    const buttonValue = clickedButton.value;
    state.current_tab = buttonValue;

    // 按鈕高亮切換
    const allButtons = document.querySelectorAll(".switch_show_button");
    allButtons.forEach(btn => {
        const isSelected = (btn === clickedButton);
        btn.classList.toggle("action", isSelected);
        btn.style.fontSize = isSelected ? "22px" : "";
    });

    const info_show_block = document.querySelector(".info_show_block");
    const info_title_name = document.querySelector(".info_title_name");
    const info_title_data = document.querySelector(".info_title_data");
    const pentest_state = document.querySelector(".pentest_state");

    if (!info_show_block) return;

    // 清空顯示區塊與標題
    info_show_block.innerHTML = "";
    if (info_title_name) info_title_name.textContent = "";
    if (info_title_data) info_title_data.textContent = "";
    if (pentest_state) pentest_state.textContent = "";

    // 分頁渲染邏輯
    switch (buttonValue) {
        case "Shared Memory":
            if (info_title_name) info_title_name.textContent = "當前共享記憶體的資料";
            render_share_memory();
            break;

        case "Tool History":
            if (info_title_name) info_title_name.textContent = "當前使用過的工具";
            render_tool_history();
            break;

        case "AI Interaction":
            if (info_title_name) info_title_name.textContent = "與 AI 的對話紀錄";
            info_show_block.innerHTML = `<div class="ai_show_block" id="ai_container">${state.ai_history}</div>`;
            scrollToBottom("ai_container");
            break;

        case "Terminal":
            if (info_title_name) info_title_name.textContent = "當前工具";
            if (info_title_data) {
                info_title_data.textContent = state.current_tool !== "" 
                    ? state.current_tool 
                    : "尚未開啟設備或是尚未使用到任何工具";
            }
            info_show_block.innerHTML = `<div class="terminal_show_block" id="terminal_container">${state.log_history}</div>`;
            scrollToBottom("terminal_container");
            break;

        case "IoT Devices":
            if (info_title_name) info_title_name.textContent = "當前設備:";
            if (info_title_data) {
                info_title_data.textContent = state.started_device !== "" ? state.started_device : "尚未選擇設備";
            }
            await render_iot_devices(info_show_block);
            break;

        default:
            console.warn(`[UI] 未知的分頁標籤: ${buttonValue}`);
            break;
    }
}

// 渲染 IoT 設備選單
async function render_iot_devices(container) {
    const devices_name = await get_devices_name();
    if (devices_name && devices_name.length > 0) {
        const devicesHTML = devices_name.map(file_name => {
            const isStarted = (file_name === state.started_device);
            return `
                <div class="device_selection_block" id="dev_${escapeHtml(file_name)}">
                    <p class="device_name">${escapeHtml(file_name)}</p>
                    <div class="device_btn_group">
                        <button class="device_button start_btn ${isStarted ? 'active' : ''}" 
                                id="start_${escapeHtml(file_name)}" 
                                onclick="start_device('${escapeHtml(file_name)}')" 
                                ${isStarted ? 'disabled' : ''}>
                            ${isStarted ? 'Running' : 'Start'}
                        </button>
                        <button class="device_button stop_btn" 
                                id="stop_${escapeHtml(file_name)}" 
                                onclick="stop_device('${escapeHtml(file_name)}')" 
                                ${!isStarted ? 'disabled' : ''}>
                            Stop
                        </button>
                    </div>
                </div>
            `;
        }).join("");
        container.innerHTML = devicesHTML;
    } else {
        container.innerHTML = `<p class="device_name" style="color: #f87171; padding: 10px;">找不到任何 IoT 設備檔案</p>`;
    }
}

// ===== 2. 滲透測試設備控制 (Start / Stop) =====
async function start_device(deviceName) {
    if (state.started_device === "") {
        state.started_device = deviceName;

        const info_title_data = document.querySelector(".info_title_data");
        if (info_title_data) info_title_data.textContent = deviceName;

        await start_pentest(deviceName);

        const currentBtn = document.querySelector(`.switch_show_button[value='IoT Devices']`);
        if (currentBtn) switch_button_state(currentBtn);
    } else if (state.started_device !== deviceName) {
        alert(`目前已有設備 [${state.started_device}] 正在執行中，請先停止它！`);
    }
}

async function stop_device(deviceName) {
    if (state.started_device === deviceName) {
        if (confirm(`確定要停止設備 [${deviceName}] 的滲透測試嗎？`)) {
            await stop_pentest();
            state.started_device = "";

            const info_title_data = document.querySelector(".info_title_data");
            if (info_title_data) info_title_data.textContent = "尚未選擇設備";

            const currentBtn = document.querySelector(`.switch_show_button[value='IoT Devices']`);
            if (currentBtn) switch_button_state(currentBtn);
        }
    }
}

// ===== 3. WebSocket 即時通訊接收器 =====
function initReceiver() {
    if (wsB && (wsB.readyState === WebSocket.OPEN || wsB.readyState === WebSocket.CONNECTING)) return;

    if (reconnectTimer) clearTimeout(reconnectTimer);

    wsB = new WebSocket(`${WS_BASE_URL}/ws/receive_b`);

    wsB.onopen = function() {
        console.log("[WebSocket] 成功連線至即時日誌接收通道");
    };

    wsB.onmessage = function(event) {
        try {
            const data = JSON.parse(event.data);
            const log_type = (data.log_type || "").toUpperCase();

            // 分流 1：AI 對話訊息
            if (log_type === "AI_PROMPT" || log_type === "AI_RESPONSE") {
                const isPrompt = log_type === "AI_PROMPT";
                const roleClass = isPrompt ? "ai_msg_prompt" : "ai_msg_response";
                const roleLabel = isPrompt ? "PROMPT / User" : "AI RESPONSE";

                const newAiHTML = `
                    <div class="ai_message_card ${roleClass}">
                        <div class="ai_msg_header">${roleLabel}</div>
                        <div class="ai_msg_body">${escapeHtml(data.log)}</div>
                    </div>
                `;
                state.ai_history += newAiHTML;

                if (state.current_tab === "AI Interaction") {
                    const aiContainer = document.getElementById("ai_container");
                    if (aiContainer) {
                        aiContainer.insertAdjacentHTML('beforeend', newAiHTML);
                        pruneContainerChildren(aiContainer, CONFIG.MAX_LOG_ENTRIES);
                        scrollToBottom("ai_container");
                    }
                }

            // 分流 2：共享記憶體更新
            } else if (log_type === "SHARE_MEMORY") {
                state.share_memory_data = data.log;

                if (state.current_tab === "Shared Memory") {
                    render_share_memory();
                }

            // 分流 3：一般 Terminal Log (INFO, TOOL, WARN, ERROR 等)
            } else {
                if (log_type === "TOOL") {
                    state.current_tool = data.log;
                    state.tool_history_logs.push(data);
                    
                    if (state.current_tab === "Tool History") {
                        render_tool_history();
                    }
                }

                const newTerminalLogHTML = `
                    <div class="log_${log_type}_section">
                        <span class="log_type_${log_type}">${log_type}</span> 
                        <span class="log_content_${log_type}">${escapeHtml(data.log)}</span>
                    </div>
                `;
                state.log_history += newTerminalLogHTML;

                if (state.current_tab === "Terminal") {
                    const termContainer = document.getElementById("terminal_container");
                    if (termContainer) {
                        termContainer.insertAdjacentHTML('beforeend', newTerminalLogHTML);
                        pruneContainerChildren(termContainer, CONFIG.MAX_LOG_ENTRIES);
                        scrollToBottom("terminal_container");
                    }
                }
            }
        } catch (e) {
            console.error("解析 WebSocket 廣播資料失敗:", e);
        }
    };

    wsB.onclose = function() {
        console.warn(`[WebSocket] 連線中斷，${CONFIG.RECONNECT_INTERVAL / 1000} 秒後自動重連...`);
        reconnectTimer = setTimeout(() => {
            initReceiver();
        }, CONFIG.RECONNECT_INTERVAL);
    };

    wsB.onerror = function(err) {
        console.error("[WebSocket 錯誤]", err);
    };
}

// ===== 4. 工具歷史紀錄 (Tool History) 渲染器 =====
function render_tool_history() {
    const info_show_block = document.querySelector(".info_show_block");
    if (!info_show_block) return;

    if (state.tool_history_logs.length === 0) {
        info_show_block.innerHTML = `<p style="color: #FFF8F0; opacity: 0.7; padding: 20px; text-align: center;">尚未收到工具執行紀錄...</p>`;
        return;
    }

    let html = `<div style="display: flex; flex-direction: column; gap: 10px; height: 100%; overflow-y: auto;">`;
    state.tool_history_logs.forEach((item, index) => {
        html += `
            <div class="tool_card">
                <div class="tool_card_header">
                    <div class="tool_title_group">
                        <span class="tool_badge">Tool #${index + 1}</span>
                        <span class="tool_name">${escapeHtml(item.log_type)}</span>
                    </div>
                </div>
                <div class="tool_card_body">
                    <div class="tool_argument">${escapeHtml(item.log)}</div>
                </div>
            </div>
        `;
    });
    html += `</div>`;

    info_show_block.innerHTML = html;
}

// ===== 5. 通用型共享記憶體 (Shared Memory) 動態渲染器 =====
function render_share_memory() {
    const info_show_block = document.querySelector(".info_show_block");
    if (!info_show_block) return;

    const rawData = state.share_memory_data;
    if (!rawData || (typeof rawData === "string" && rawData.trim() === "")) {
        info_show_block.innerHTML = `<div class="memory_empty_notice">尚未收到共享記憶體更新資料...</div>`;
        return;
    }

    let parsedData;
    try {
        parsedData = (typeof rawData === "string") ? JSON.parse(rawData) : rawData;
    } catch (e) {
        info_show_block.innerHTML = `<div class="memory_show_block">${escapeHtml(String(rawData))}</div>`;
        return;
    }

    let html = `<div class="memory_dashboard">`;
    html += renderGenericJson(parsedData, 0);

    html += `
        <details class="raw_json_details">
            <summary>📄 檢視原始 JSON 資料 (Raw JSON)</summary>
            <div class="memory_show_block">${escapeHtml(JSON.stringify(parsedData, null, 2))}</div>
        </details>
    `;
    html += `</div>`;

    info_show_block.innerHTML = html;
}

// 遞迴解析任意 JSON 物件/陣列結構
function renderGenericJson(data, level = 0) {
    if (data === null || data === undefined) {
        return `<span class="val_null">null</span>`;
    }

    if (typeof data !== "object") {
        return `<span class="val_primitive">${escapeHtml(String(data))}</span>`;
    }

    // 陣列處理
    if (Array.isArray(data)) {
        if (data.length === 0) return `<div class="val_empty">[ 空清單 ]</div>`;

        const isArrayOfObjects = data.every(item => typeof item === "object" && item !== null && !Array.isArray(item));

        if (isArrayOfObjects) {
            const allKeys = Array.from(new Set(data.flatMap(item => Object.keys(item))));

            let tableHtml = `<div class="table_responsive"><table class="mem_table"><thead><tr>`;
            allKeys.forEach(k => {
                tableHtml += `<th>${escapeHtml(formatKeyName(k))}</th>`;
            });
            tableHtml += `</tr></thead><tbody>`;

            data.forEach(item => {
                tableHtml += `<tr>`;
                allKeys.forEach(k => {
                    const val = item[k];
                    tableHtml += `<td>${val !== undefined ? renderGenericJson(val, level + 1) : '<span class="val_null">-</span>'}</td>`;
                });
                tableHtml += `</tr>`;
            });

            tableHtml += `</tbody></table></div>`;
            return tableHtml;
        } else {
            let listHtml = `<div class="generic_array_group">`;
            data.forEach(item => {
                listHtml += `<div class="array_tag_item">${renderGenericJson(item, level + 1)}</div>`;
            });
            listHtml += `</div>`;
            return listHtml;
        }
    }

    // 物件處理
    const entries = Object.entries(data);
    if (entries.length === 0) return `<div class="val_empty">{ 空物件 }</div>`;

    const primitives = entries.filter(([_, v]) => typeof v !== "object" || v === null);
    const complex = entries.filter(([_, v]) => typeof v === "object" && v !== null);

    let objHtml = "";

    if (primitives.length > 0) {
        const gridContent = primitives.map(([k, v]) => `
            <div class="mem_info_item">
                <span class="mem_label">${escapeHtml(formatKeyName(k))}:</span>
                <span class="mem_val">${escapeHtml(String(v))}</span>
            </div>
        `).join("");

        if (level === 0) {
            objHtml += `
                <div class="mem_card">
                    <div class="mem_card_title">📌 基本屬性 (Properties)</div>
                    <div class="mem_info_grid">${gridContent}</div>
                </div>
            `;
        } else {
            objHtml += `<div class="mem_info_grid" style="margin-bottom: 10px;">${gridContent}</div>`;
        }
    }

    complex.forEach(([k, v]) => {
        const title = formatKeyName(k);
        objHtml += `
            <div class="mem_card">
                <div class="mem_card_title">📂 ${escapeHtml(title)}</div>
                <div class="mem_card_body">
                    ${renderGenericJson(v, level + 1)}
                </div>
            </div>
        `;
    });

    return objHtml;
}

// 格式化 Key 名稱 (例：device_information -> Device Information)
function formatKeyName(key) {
    return String(key)
        .replace(/([a-z])([A-Z])/g, '$1 $2')
        .replace(/[_-]+/g, ' ')
        .replace(/\b\w/g, l => l.toUpperCase());
}

// ===== 6. 輔助函式與 API 呼叫 =====
function scrollToBottom(containerId) {
    requestAnimationFrame(() => {
        const container = document.getElementById(containerId);
        if (container) {
            container.scrollTop = container.scrollHeight;
        }
    });
}

// 修剪過多的舊 DOM 節點以增進效能
function pruneContainerChildren(container, maxCount) {
    while (container.children.length > maxCount) {
        container.removeChild(container.firstChild);
    }
}

function escapeHtml(text) {
    return String(text)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

async function get_devices_name() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/pentest/get_devices_list`, {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });

        if (response.ok) {
            const data = await response.json();
            return data.files_name || [];
        } else {
            return [];
        }
    } catch (error) {
        console.error("取得裝置清單失敗:", error);
        return [];
    }
}

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

async function stop_pentest() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/pentest/stop_pentest`, {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });

        if (response.ok) {
            const data = await response.json();
            console.log(`[Pentest] ${data.message}`);
        } else {
            console.error("發送停止請求失敗");
        }
    } catch (error) {
        console.error("無法發送停止滲透測試請求:", error);
    }
}

function pentest_button_init() {
    const firstButton = document.querySelector(".switch_show_button");
    if (firstButton) {
        switch_button_state(firstButton);
    }
}

// 頁面初始化與卸載事件
window.addEventListener("DOMContentLoaded", () => {
    initReceiver();
    pentest_button_init();
});

window.addEventListener("beforeunload", () => {
    if (wsB) {
        wsB.onclose = null; // 避免離開頁面時觸發重連機制
        wsB.close();
    }
});
```


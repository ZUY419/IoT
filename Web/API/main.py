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
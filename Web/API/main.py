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

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
import json
from datetime import datetime
import os
import re
from pathlib import Path

def pretty_print_json(data, indent=4):
    """
    將 Python 字典（dict）或字串格式化為高可讀性的 JSON 輸出
    """
    if isinstance(data, str):
        try:
            # 如果傳進來的是 JSON 字串，先轉成 dict
            data = json.loads(data)
        except json.JSONDecodeError:
            # 如果不是合法的 JSON 字串，就直接印出原本的文字
            print(data)
            return

    # 自訂序列化處理（例如遇到時間物件時轉成字串）
    def default_serializer(obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Type {type(obj)} not serializable")

    # 進行 json.dumps 格式化
    formatted_str = json.dumps(
        data, 
        indent=indent, 
        ensure_ascii=False,  # 確保中文不會被跳脫成 Unicode 碼
        sort_keys=False,     # 是否按 Key 字母排序（通常保持 False 比較符合邏輯順序）
        default=default_serializer
    )
    
    print(formatted_str)

def get_folder():
    return Path(__file__).resolve().parent

def read_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
    
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
            
        print(f"[✏️ 檔案寫入成功] 資料已成功儲存至: {path}")
        return True
        
    except Exception as e:
        print(f"[❌ 檔案寫入失敗] 路徑 {path} 寫入異常: {str(e)}")
        return False

def get_current_folder_path():
    """
    取得目前腳本所在的絕對資料夾路徑
    """
    # 適用於一般 .py 執行檔或腳本
    return os.path.dirname(os.path.abspath(__file__))

def clean_version(version_str):
    if not version_str:
        return ""
    
    cleaned = version_str.replace("/", " ")
    
    # 嘗試抓出包含數字的版本號格式
    match = re.search(r'(\d+(\.\d+)+[a-zA-Z0-9-]*)', cleaned)
    if match:
        result = match.group(1)
        # 🛡️ 額外防呆：確保抓到的結果裡面真的包含數字，避免把純英文（如 "Unbound"）當作版號
        if any(char.isdigit() for char in result):
            return result
            
    # 如果沒有抓到帶數字的版號，直接回傳空字串！
    return ""

def remove_version(text):
    if not text:
        return ""
    
    # 1. 這裡用你原本抓版本號的 Regex 邏輯
    # 它會抓出類似 2.41, 1.4.28, v1.0-beta 等版本號格式
    version_pattern = r'(\d+(\.\d+)+[a-zA-Z0-9-]*)'
    
    # 2. 用 re.sub 把符合版本號的片段替換成空字串 ""
    cleaned_text = re.sub(version_pattern, '', text)
    
    # 3. 清理多餘的空白字元與結尾符號
    cleaned_text = cleaned_text.strip()
    
    return cleaned_text

folder = get_folder()
share_memory_file = folder / "data" / "share memory" / "share memory.json"

def print_and_write_share_momery(data):
    print("-" * 80 + " Share Memory")
    write_json(share_memory_file, data)
    pretty_print_json(data)
    print("-" * 80)
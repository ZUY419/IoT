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
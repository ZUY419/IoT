import os
from pathlib import Path
from langchain_ollama import OllamaLLM
from ollama import Client

# =============================================================================
# 1. 統一全域設定 (模型與環境變數)
# =============================================================================
OLLAMA_MODEL = "qwen2.5-coder:7b"
OLLAMA_HOST = "http://ollama:11434"

# =============================================================================
# [NEW] 🎯 目標與沙盒設定 (Target & Workspace Configuration)
# =============================================================================
# 這裡從 .yml 變數讀取目標 IP，如果沒設定，預設為 D-Link 靶機的 192.168.0.1
TARGET_IP = os.getenv("PENTEST_TARGET", "192.168.0.1")

# 設定工作沙盒路徑 (當前目錄下的 workspace 資料夾)
WORKSPACE_DIR = Path.cwd() / "workspace"

# 【自動初始化沙盒】只要 config.py 被載入，自動確保 workspace 資料夾存在，防止工具噴 FileNotFoundError
try:
    WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
except Exception as e:
    print(f"[Config Warning] 無法建立工作沙盒目錄: {e}")

# =============================================================================
# 2. 提供給未來如果想用 LangChain 模組的初始化
# =============================================================================
llm = OllamaLLM(
    model=OLLAMA_MODEL,
    base_url=OLLAMA_HOST
)

# =============================================================================
# 3. 提供給我們目前 main.py 原生感知模組使用的 Client
# =============================================================================
def get_ollama_client():
    """
    初始化並回傳 Ollama 客戶端實例
    """
    try:
        client = Client(host=OLLAMA_HOST)
        return client
    except Exception as e:
        print(f"[Config Error] 無法初始化 Ollama 客戶端: {e}")
        return None

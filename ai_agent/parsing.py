import json

from .prompt import get_stage1_system_prompt, get_stage2_system_prompt, get_stage3_system_prompt
from .call_ollama import _call_ollama_and_parse_json

def ai_parsing_module(raw_log, prior_context="", orchestrator=None):
    """【Stage 1: 感知模組】分析最新 Nmap/掃描日誌，回傳標準化 JSON"""
    print("\n[感知模組 Stage 1] 正在叫 Qwen2.5-Coder 分析最新日誌...")
    
    # 💡 確保安全處理 Dictionary 或 String 格式的 raw_log
    if isinstance(raw_log, (dict, list)):
        formatted_log_str = json.dumps(raw_log, indent=2, ensure_ascii=False)
    else:
        formatted_log_str = str(raw_log)
        
        # 保留原本對傳統 Nmap 文字 Log 的過濾與美化邏輯
        if "PORT STATE SERVICE" in formatted_log_str or "/tcp" in formatted_log_str:
            cleaned_lines = []
            for line in formatted_log_str.split('\n'):
                if "/tcp" in line or "/udp" in line or "PORT" in line:
                    cleaned_lines.append(line.strip())
            if len(cleaned_lines) > 1:
                formatted_log_str = "\n".join(cleaned_lines)
    
    system_prompt = get_stage1_system_prompt(orchestrator)
    user_content = f"""{prior_context}

=== NEW EXECUTED RAW LOG TO ANALYZE ===
{formatted_log_str}"""
    
    return _call_ollama_and_parse_json(system_prompt, user_content, "Stage 1")

def ai_parsing_stage2(raw_log: str, prior_context: str = "") -> dict:
    """
    【Stage 2: 推理模組】
    解析預先排序好的 CVE 報告，進行目標選擇與 RAG 檢索語句生成。
    """
    print("\n[🧠 推理模組 Stage 2] 正在分析 CVE 報告並鎖定利用目標 (PentestGPT Mode)...")
    
    # 1. 載入獨立管理之 System Prompt
    system_prompt = get_stage2_system_prompt()
    
    # 2. 組裝 User Content
    user_content = f"""{prior_context}

=== NVD SEARCHED CVE REPORT TO EVALUATE ===
{raw_log}"""

    # 3. 呼叫 LLM 進行推理並解析 JSON
    parsed_result = _call_ollama_and_parse_json(system_prompt, user_content, "Stage 2 Reasoning")
    
    # 4. 終端機日誌列印
    if parsed_result and parsed_result.get("status") == "success":
        stage2_info = parsed_result.get("stage2_status", {})
        target_cve = stage2_info.get("selected_target_cve", "None")
        reason = stage2_info.get("reason", "No reason provided.")
        rag_query = stage2_info.get("rag_search_query", "None")
        
        print(f"  └─ 🎯 [推理決策] 鎖定目標 CVE: \033[91m{target_cve}\033[0m")
        print(f"  └─ 💡 [決策邏輯]: {reason}")
        print(f"  └─ 🔍 [RAG 檢索指令]: {rag_query}")
    else:
        print("  └─ ⚠️ [推理失敗] 無法產出有效決策，請檢查 LLM 輸出內容。")

    return parsed_result

def ai_parsing_stage3(raw_log, prior_context=""):
    """【Stage 3: 決策生成模組 (Generation)】根據推理結果，生成或決定攻擊 Payload 執行方案"""
    print("\n[生成模組 Stage 3] 正在規劃具體攻擊 Payload 與利用鏈步驟...")
    
    # 這裡如果你有定義 get_stage3_system_prompt，請改用它
    # 目前先用 stage2 或通用範本墊底以防報錯
    try:
        from prompt import get_stage3_system_prompt
        system_prompt = get_stage3_system_prompt()
    except ImportError:
        print("[!] 警告: 未在 prompt.py 找到 get_stage3_system_prompt，暫時借用 Stage 2 模版")
        system_prompt = get_stage2_system_prompt()

    user_content = f"""{prior_context}

=== LAST EXPLOIT EXECUTION RESULT ===
{raw_log}"""
    
    return _call_ollama_and_parse_json(system_prompt, user_content, "Stage 3")

import os
import sys
import json
import re

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import util
from config.config import get_ollama_client, OLLAMA_MODEL, TARGET_IP
from .tool_config import TOOL_DESCRIPTION

share_memory_file = util.share_memory_file
ollama_client = get_ollama_client()

def _call_ollama_and_parse_json(system_prompt, user_content, stage_name="LLM"):
    """發送請求給 Ollama，並利用 Regex 強制清洗出合法的 Python dict"""
    raw_reply = ""

    share_memory_data = util.read_json(share_memory_file)
    memory_str = json.dumps(share_memory_data, ensure_ascii=False, indent=2)

    try:
        response = ollama_client.chat(
            model=OLLAMA_MODEL,
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"{user_content}\n\n--- 📂 Current Shared Memory State ---\n{memory_str}"}
            ],
            tools=TOOL_DESCRIPTION,
            format="json",
            options={'temperature': 0.0}
        )
        raw_reply = response['message']['content'].strip()
        
        # 剝離 Markdown Code Block (```json ... ```)
        clean_text = re.sub(r'```json|```', '', raw_reply).strip()
        
        # 擷取 JSON 區塊 { ... }
        match = re.search(r'\{.*\}', clean_text, re.DOTALL)
        clean_json_text = match.group(0) if match else clean_text
        
        # 修復數字 Key 沒有加雙引號的狀況
        clean_json_text = re.sub(r'([{,]\s*)(\d+)(\s*:) ', r'\1"\2"\3 ', clean_json_text)
        
        result = json.loads(clean_json_text)
        return result
        
    except Exception as e:
        print(f"[!] {stage_name} 模組發生未知錯誤: {e}")
        print(f"原始回傳：\n{raw_reply}\n--------------------")
        return {"status": "error", "reason": str(e), "recommended_next_steps": ["NONE"]}

def get_Client_ollama(prompt):
    try:
        response = ollama_client.chat(
            model=OLLAMA_MODEL,
            messages = prompt,
            tools=TOOL_DESCRIPTION,
            format="json",
            options={'temperature': 0.0}
        )

        return response
    except Exception as e:
        print("get_Client Error")

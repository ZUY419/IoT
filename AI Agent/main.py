# AI Agent/main.py
import sys
import time
import json
import re
import os
from dotenv import load_dotenv

import util
from tools import NetworkTools, PentestToolbox
import ai.ollama as ollama
import ai.prompt as prompt
from config.logging import log_info

load_dotenv()

# 從 .env 或 ai.prompt 讀取目標 IP
TARGET_IP = os.getenv("TARGET_IP", prompt.TARGET_IP)

class PentestBox:
    def __init__(self):
        # 初始化輪數與階段設定
        self.turn = 0
        self.current_state = 1  # 1: 資產偵察, 2: 漏洞評估/攻擊
        self.max_steps = 8

        # 初始化網路掃描工具 (供固定 SOP 使用)
        self.net_tools = NetworkTools(TARGET_IP)

        # 初始化共享記憶體 (Share Memory)
        self.share_memory = {
            "device_information": {
                "device_type": "IoT Device",
                "target_ip": TARGET_IP
            },
            "history_logs": [],
            "current_observation": prompt.INITIAL_USER_PROMPT
        }

        # 寫入初始 Share Memory 並與 config.logging / JSON 檔案持久化同步
        log_info.share_memory(self.share_memory)

    def run_fixed_initial_recon(self):
        """
        【固定 SOP 流程】第一階段啟動前置掃描
        利用重構後的 nmap_scan_tcp 進行安全且防當機的 TCP 基礎開埠探測
        """
        log_info.info("⚙️ 執行固定 SOP：發起安全 TCP 全埠探測 (含防當機保護)...")
        
        # 1. 執行重構後的 TCP 溫柔掃描 (內建敏感埠 80/443 避坑邏輯)
        tcp_results = self.net_tools.nmap_scan_tcp()
        
        # 2. 將固定掃描結果格式化轉換為 AI 的初始 Observation 上下文
        formatted_ports = []
        for port, info in tcp_results.items():
            formatted_ports.append(f"- Port {port}/TCP: {info['name']} (Version: {info['version']})")
        
        ports_summary = "\n".join(formatted_ports) if formatted_ports else "未發現開放的 TCP 通訊埠"

        initial_obs = f"""【固定 SOP 預掃描完成】
目標 IP: {TARGET_IP}
TCP 開放服務結果:
{ports_summary}

請根據上述已獲取的開埠資產情報，開始針對特定開放服務進行詳細分析與後續偵察決策。
"""
        # 更新共享記憶體
        self.share_memory["current_observation"] = initial_obs
        
        # 紀錄第一筆 SOP 歷史
        self.share_memory["history_logs"].append({
            "step": 0,
            "thought": "執行固定 SOP 基礎 TCP 探測",
            "command": "NetworkTools.nmap_scan_tcp()",
            "output": json.dumps(tcp_results, ensure_ascii=False)
        })

        # 自動持久化同步寫入 data/share memory/share memory.json
        log_info.share_memory(self.share_memory)
        log_info.info("✅ 固定 SOP 預掃描完成，已將基礎開埠情報載入 Share Memory！")

    def parse_json_response(self, raw_text):
        """解析 LLM 回傳的 JSON 決策內容 (支援 Markdown ```json 標籤過濾)"""
        if not raw_text:
            return None
        try:
            match = re.search(r'\{.*\}', raw_text, re.DOTALL)
            if match:
                return json.loads(match.group(0))
            return json.loads(raw_text)
        except Exception as e:
            log_info.error(f"JSON 解析失敗: {e}")
            return None

    def pentestPipeLine(self):
        log_info.info("🚀 滲透測試 Agent 正式啟動！")

        # 🌟 步驟 1：先執行固定 SOP 流程（取得安全且精準的基礎開埠情報）
        self.run_fixed_initial_recon()

        # 🌟 步驟 2：接著進入 AI 動態推演 ReAct 迴圈
        while True:
            try:
                self.turn += 1
                log_info.info(f"\n>>> 🔄 第 {self.turn} 輪: 當前為第 {self.current_state} 階段 (AI 動態推演)")

                # 1. 組合 Prompt (System Prompt + 近3輪歷史紀錄 + 當前 Observation)
                full_prompt = f"{prompt.SYSTEM_PROMPT_STAGE_1}\n\n"
                
                history = self.share_memory.get("history_logs", [])
                if history:
                    full_prompt += "【過往執行歷史】:\n"
                    for h in history[-3:]:
                        full_prompt += f"- 執行指令: {h['command']}\n  結果: {h['output'][:300]}...\n"

                full_prompt += f"\n【當前觀測狀態 (Observation)】:\n{self.share_memory['current_observation']}\n"

                # 2. 印出與發送 Prompt 至 Ollama API
                log_info.AI_prompt(full_prompt)
                raw_response = ollama.call_ollama(full_prompt)
                log_info.AI_response(raw_response)

                # 3. 解析 AI 的 JSON 決策
                decision = self.parse_json_response(raw_response)
                if not decision:
                    log_info.warn("無法取得有效 JSON 決策，結束本輪測試。")
                    break

                thought = decision.get("thought", "無說明理由")
                command = decision.get("command", "")
                stage_completed = decision.get("stage_completed", False)

                log_info.info(f"[🧠 思考決策]: {thought}")

                # 4. 判斷階段完成條件或到達輪數上限
                if stage_completed or not command or self.turn >= self.max_steps:
                    log_info.info("🎉 第一階段（資產偵察）宣告完成！")
                    log_info.share_memory(self.share_memory)
                    break

                # 5. 透過 PentestToolbox 執行 CLI 指令
                output = PentestToolbox.execute_cli(command)
                log_info.info(f"[👁️ 觀測結果]: {output[:200]}...")

                # 6. 更新 self.share_memory 狀態並同步寫入檔案
                self.share_memory["history_logs"].append({
                    "step": self.turn,
                    "thought": thought,
                    "command": command,
                    "output": output
                })
                self.share_memory["current_observation"] = f"上一輪執行指令 `{command}` 的回傳結果為:\n{output}"

                # 自動寫入 data/share memory/share memory.json
                log_info.share_memory(self.share_memory)

                time.sleep(2)

            except KeyboardInterrupt:
                log_info.warn("\n[!] 使用者手動中斷滲透測試，同步當前記憶體資料中...")
                log_info.share_memory(self.share_memory)
                log_info.info("滲透測試結束")
                break

if __name__ == "__main__":
    pentext = PentestBox()
    pentext.pentestPipeLine()
import subprocess
import re
import json
from pathlib import Path
from config.logging import log_info
import util

class NetworkTools:
    def __init__(self, target_ip: str):
        self.target_ip = target_ip

    def nmap_scan_tcp(self, sensitive_ports: set = None) -> dict:
        """
        執行全埠 (1-65535) TCP 掃描。
        針對 IoT 設備優化：
        1. 自動略過已知敏感或易當機的埠（如 80, 443, 8080, 8443）。
        2. 對發現的非敏感開放埠進行深度版本探測 (-sV)。
        3. 統一規格：version 若無法辨識則保持 "unknown"。
        """
        log_info.tool("nmap_scan_tcp")
        scan_results = {}

        if sensitive_ports is None:
            sensitive_ports = {"80", "443", "8080", "8443"}

        try:
            log_info.info(f"正在對目標 {self.target_ip} 執行全 TCP 埠 (1-65535) 快速探測...")
            
            # 第一階段：快速全埠掃描
            command = [
                "nmap",
                "-sT",
                "-p-",
                "--max-rate", "1000",
                "--host-timeout", "120s",
                self.target_ip,
            ]
            
            result = subprocess.run(
                command, capture_output=True, text=True, check=False, timeout=130
            )
            stdout = result.stdout
            
            matches = re.findall(r'(\d+)/tcp\s+([a-zA-Z|]+)\s+([^\n]*)', stdout)
            
            open_ports = []
            for port_str, state, info in matches:
                port_str = str(port_str)
                if state == "open":
                    open_ports.append((port_str, info))

            # 第二階段：針對發現的開放埠進行分類處理
            for port_str, info in open_ports:
                
                # 🛡️ 敏感埠處理 (略過詳細版本探測以防 FAP/IoT 設備崩潰)
                if port_str in sensitive_ports:
                    log_info.info(f"發現敏感埠 {port_str} (狀態: open)，已略過自動版本探測以防當機。")
                    parts = info.strip().split() if info.strip() else []
                    service_name = parts if parts else "http"
                    scan_results[port_str] = {
                        "name": service_name,
                        "version": "unknown"
                    }
                    continue

                # 💡 非敏感埠：執行深度版本掃描 (-sV)
                log_info.info(f"正在對非敏感埠 {port_str} 進行深度版本偵測...")
                deep_command = [
                    "nmap",
                    "-sT",
                    "-p", port_str,
                    "-sV",
                    "--version-intensity", "5",
                    self.target_ip,
                ]
                
                deep_result = subprocess.run(
                    deep_command, capture_output=True, text=True, check=False, timeout=30
                )
                deep_match = re.search(rf'{port_str}/tcp\s+open\s+([^\s]+)\s*([^\n]*)', deep_result.stdout)
                
                if deep_match:
                    service = deep_match.group(1)
                    version_raw = deep_match.group(2).strip()
                    if version_raw and "service unrecognized" not in version_raw.lower():
                        version = version_raw
                    else:
                        version = "unknown"
                else:
                    parts = info.strip().split(maxsplit=1) if info.strip() else []
                    service = parts if len(parts) > 0 else "unknown"
                    version = "unknown"

                scan_results[port_str] = {
                    "name": service,
                    "version": version
                }
                log_info.info(f"Port {port_str} Open | Service: {service} | Version: {version}")

        except subprocess.TimeoutExpired:
            log_info.error(f"TCP 掃描超時：目標 {self.target_ip} 無回應")
        except Exception as e:
            log_info.error(f"TCP 全埠掃描發生異常: {e}")

        return scan_results

    def nmap_scan_udp(self, port=None) -> dict:
        """
        逐個 Port 進行 UDP 掃描與版本探測，帶有本機 JSON 快取機制，避免重複對特定 Port 進行掃描。
        """
        log_info.tool("nmap_scan_udp")

        # 🛡️ 傳入參數防呆規格化
        if port is None:
            port_list = ["53", "67", "69", "161", "1900", "5000", "5351"]
        elif isinstance(port, str):
            port_list = [p.strip() for p in port.replace("U:", "").split(",") if p.strip()]
        elif isinstance(port, (list, tuple)):
            port_list = [str(p).replace("U:", "").strip() for p in port if str(p).strip()]
        else:
            log_info.warn("收到無效的 port 型態，使用預設 UDP 清單。")
            port_list = ["53", "67", "69", "161", "1900", "5000", "5351"]
            
        folder = Path(util.get_current_folder_path())
        safe_target = re.sub(r"[^A-Za-z0-9_.-]", "_", str(self.target_ip))
        json_path = folder / "data" / "nmap" / f"udp-{safe_target}.json"
        
        # 讀取現有快取
        udp_data = {}
        if json_path.exists():
            try:
                udp_data = util.read_json(json_path) or {}
            except Exception as e:
                log_info.warn(f"讀取 UDP 快取失敗，將建立新紀錄: {e}")
                udp_data = {}

        # 濾掉已經掃描過的埠
        ports_to_scan = [p for p in port_list if p not in udp_data]
        scan_results = udp_data.copy()

        for p in ports_to_scan:
            try:
                log_info.info(f"正在對 UDP Port {p} 進行探測...")
                command = [
                    "nmap",
                    "-sU",
                    "-p", p,
                    "-sV",
                    "--max-rate", "30",
                    "--max-retries", "1",
                    self.target_ip,
                ]
                
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=15
                )
                
                stdout = result.stdout
                stderr = result.stderr
                
                if stderr.strip():
                    log_info.error(f"Port {p} 錯誤: {stderr.strip()}")
                
                # 解析 Nmap 輸出
                match = re.search(rf'{p}/udp\s+([a-zA-Z|]+)\s*([^\n]*)', stdout)
                
                if match:
                    state = match.group(1)
                    if "closed" in state:
                        continue

                    extra = match.group(2).strip()
                    parts = extra.split(maxsplit=1) if extra else []
                    service = parts if len(parts) > 0 else "unknown"
                    version = parts if len(parts) > 1 else "unknown"
                    
                    scan_results[str(p)] = {
                        "name": service,
                        "version": version
                    }
                    log_info.info(f"Port {p} Status: {state} | Service: {service} | Version: {version}")
                else:
                    scan_results[str(p)] = {
                        "name": "unknown",
                        "version": "unknown"
                    }
                    log_info.info(f"Port {p} 無明確回應 (closed/filtered)")

            except subprocess.TimeoutExpired:
                log_info.error(f"UDP Port {p} 掃描超時 (超過 15 秒)，自動跳過")
                scan_results[str(p)] = {
                    "name": "unknown",
                    "version": "unknown"
                }
            except Exception as e:
                log_info.error(f"UDP Port {p} 掃描發生異常: {e}")
                scan_results[str(p)] = {
                    "name": "unknown",
                    "version": "unknown"
                }

        # 自動確保資料夾存在並寫入快取
        json_path.parent.mkdir(parents=True, exist_ok=True)
        util.write_json(json_path, scan_results)
        log_info.info(f"UDP 掃描結果已更新並寫入快取: {json_path}")

        return scan_results

    def execute_cli(command, timeout=120):
            """執行 Linux CLI 命令並記錄"""
            log_info.tool(command)
            try:
                result = subprocess.run(
                    command, shell=True, capture_output=True, text=True, timeout=timeout
                )
                stdout = result.stdout.strip()
                stderr = result.stderr.strip()
                output = stdout if stdout else stderr
    
                # 長文本截斷，防止過長 Log 塞爆 Context Window
                if len(output) > 1500:
                    output = output[:800] + "\n\n...[過長 Log 已自動截斷]...\n\n" + output[-700:]
    
                return output if output else "（指令執行成功，但無文字輸出）"
            except subprocess.TimeoutExpired:
                log_info.warn(f"指令 `{command}` 執行超過 {timeout} 秒超時")
                return f"（錯誤：指令 `{command}` 執行超過 {timeout} 秒超時）"
            except Exception as e:
                log_info.error(f"執行發生例外狀況: {e}")
                return f"（執行發生例外狀況: {e}）"
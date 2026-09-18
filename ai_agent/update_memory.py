
def _update_stage1_memory(self, perception_result: dict):
    """解析 Stage 1 的 JSON，更新服務與版本記憶（純資產盤點，不涉及 CVE/NVD）"""
    services = perception_result.get("services", {})
    open_ports = perception_result.get("open_ports", [])
    
    # 1. 初始化或取得現有的巢狀結構
    if "discovered_services" not in self.shared_memory:
        self.shared_memory["discovered_services"] = {
            "tcp": {},
            "udp": {}
        }
    
    all_service = self.shared_memory["discovered_services"]

    # 2. 優先處理服務與版本建檔 (支援 "53/tcp" 或純數字)
    for port_protocol, info in services.items():
        if "/" in port_protocol:
            port, protocol = port_protocol.split("/", 1)
        else:
            port = port_protocol
            protocol = "tcp"  # 預設協定防呆

        # 確保該 protocol 分類存在
        if protocol not in all_service:
            all_service[protocol] = {}

        # 取得目前舊資料 (如果有的話) 以便做增量保護
        current_node = all_service[protocol].get(port, {})
        
        service_name = info.get("service", info.get("name", "unknown"))
        service_version = info.get("version", "unknown")

        # 增量覆蓋：只在拿到「非 unknown」且「非 -」的新資訊時覆蓋舊資訊
        final_name = service_name if service_name not in ["unknown", "-"] else current_node.get("name", "unknown")
        final_version = service_version if service_version not in ["unknown", "-"] else current_node.get("version", "unknown")

        all_service[protocol][port] = {
            "name": final_name,
            "version": final_version
        }

    # 3. 確保所有 open_ports 也有基本建檔 (防呆：避免漏掉沒有詳細 service 資訊的 port)
    for p in open_ports:
        p_str = str(p)
        # 預設檢查 tcp，若沒有則補上基本未知節點
        if p_str not in all_service["tcp"] and p_str not in all_service["udp"]:
            all_service["tcp"][p_str] = {
                "name": "unknown",
                "version": "unknown"
            }

    self.shared_memory["discovered_services"] = all_service

    # 4. 同步到 TaskTree 的 scanned_ports！
    if hasattr(self, "task_tree"):
        flattened_scanned_ports = {
            "tcp": {},
            "udp": {}
        }
        
        # 遍歷 tcp / udp 外層
        for proto, ports_dict in self.shared_memory["discovered_services"].items():
            # 確保內層 key 存在
            if proto not in flattened_scanned_ports:
                flattened_scanned_ports[proto] = {}
                
            # 遍歷內層的 port 與對應的 service 資訊
            for port, info in ports_dict.items():
                flattened_scanned_ports[proto][port] = {
                    "service": info.get("name", "unknown"),
                    "version": info.get("version", "unknown")
                }
                
        self.task_tree.scanned_ports = flattened_scanned_ports

def _update_stage2_memory(self, perception_result: dict):
    """解析 Stage 2 的 JSON，更新漏洞評估與目標選擇記憶"""
    if not isinstance(perception_result, dict):
        return
    
    stage2_info = perception_result.get("stage2_status", {})

    # 1. 保存/更新比對出的 CVE 清單
    matched = stage2_info.get("matched_cves", [])
    if matched:
        self.shared_memory["mapped_cves"] = matched
    
    #2. 存入 Stage 2 最終精選的「當前焦點 CVE」與「推理決策」
    if "selected_target_cve" in stage2_info:
        self.shared_memory["current_target_cve"] = stage2_info.get("selected_target_cve")
        self.shared_memory["target_reasoning"] = stage2_info.get("reason", "")
        self.shared_memory["rag_query"] = stage2_info.get("rag_search_query", "")

def _update_stage3_memory(self, perception_result: dict):
    """解析 Stage 3 的 JSON，如果 Exploit 失敗，記錄失敗原因"""
    # 假設 Stage 3 回傳攻擊狀態
    exploit_status = perception_result.get("exploit_status", {})
    if exploit_status.get("result") == "FAILED":
        self.shared_memory["tried_exploits"].append({
            "cve": exploit_status.get("targeted_cve"),
            "reason": exploit_status.get("error_message", "Unknown execution error")
        })
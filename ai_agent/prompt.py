import json
from .tool_config import TOOL_DESCRIPTION

# =============================================================================
# Shared prompt fragments 
# =============================================================================

_IDENTITY = (
    "You are PentestGPT, an AI-powered automated penetration testing assistant specializing in IoT and firmware security."
)

def _format_tools_from_config() -> str:
    tool_descriptions = []
    for tool in TOOL_DESCRIPTION:
        name = tool.get("name")
        desc = tool.get("description")
        tool_descriptions.append(f"- {name}: {desc}")
    return "\n".join(tool_descriptions)

_STAGE1_TOOLS = """TOOLS & CAPABILITIES (Stage 1: Reconnaissance & Enumeration Only):
You have access to information gathering and enumeration tools ONLY:
- nmap, masscan - Port scanning, service enumeration, and protocol-specific auditing
- gobuster, ffuf, dirb - Directory, file, and endpoint brute-forcing
- curl, wget - HTTP/HTTPS banner grabbing, header analysis, and API endpoint discovery"""

_STAGE3_TOOLS = """TOOLS & CAPABILITIES (Stage 3: Vulnerability Exploitation & Post-Exploitation):
You have full authorization to execute active exploitation tools based on CVE analysis:
- sqlmap - Automated SQL injection testing and database exploitation
- Custom scripts - Write and execute python exploit code, automated PoC triggers, and tailored payloads
- netcat, socat - Network connections, port forwarding, and establishing reverse shells
- john, hashcat - Password hash cracking and credential recovery
- curl, wget - Triggering remote code execution (RCE) endpoints, sending exploit payloads, or downloading post-exploitation scripts"""

_CRITICAL_RULES = """CRITICAL RULES FOR ACCURACY & MINDSET:
1. Do NOT hallucinate. If the raw log shows NO open ports, then 'open_ports' MUST be [], 'services' MUST be {}, and 'asset_inventory_table' MUST strictly state that no open ports were found.
2. Do NOT copy any example values into your final output if they are not explicitly mentioned in the raw log.
3. ATTACKER MINDSET: You are a Red Team / Penetration Tester. Your 'recommended_next_steps' MUST be offensive, actionable commands or tool suggestions to find vulnerabilities. Do NOT provide defensive patching, password changing, or firewall advice.

CRITICAL TRAFFIC REGULATION & FRAGILE PORT PROTECTION (ANTI-CRASH):
8. WEBSERVER STABILITY GUARD: Web ports (e.g., HTTP 80, HTTPS 443) on embedded/IoT targets are extremely fragile and prone to service crashes. Your 'recommended_next_steps' MUST ABSOLUTELY AVOID high-frequency, noisy brute-force directory scanning or heavy automated vulnerability scans (such as running heavy gobuster, dirb, or aggressive scans) that will exhaust connection backlogs.
9. PRECISE EXPLOITATION ONLY: Active vulnerability exploitation is fully allowed and encouraged, but it MUST be executed via a single, precise, targeted payload (e.g., a one-shot exploit or custom PoC script). Do NOT poke, hammer, or flood the fragile web server with unnecessary probes. If a robust alternative service has high-severity, reliable CVEs available, prioritize exploring that channel.
10. TOOL DIVERSITY & ANTI-REPETITION: Do NOT use the exact same tool or command sequence that was used in the immediately preceding turn for the same objective. If a tool was already executed on a target service, you MUST pivot to a different tool, a deeper manual script, a specific exploit module, or a different reconnaissance/exploitation angle to avoid redundant scans and ensure progressive coverage.

CRITICAL STATE-KEEPING & MEMORY RULES (ANTI-AMNESIA):
4. 'open_ports' and 'services' are CUMULATIVE fields. They MUST represent the entire history of the target across the timeline, NOT just the current turn.
5. NEVER remove any previously discovered port from the 'open_ports' list or 'services' map. If port 53 or 80 was found in Turn 1, it MUST remain in 'open_ports' in Turn 2, Turn 3, and all future turns.
6. The latest raw log may focus on only one port, but you MUST MERGE this new tool knowledge with the 'prior_context' to maintain a complete, unbroken asset inventory.
7. If you violate this, drop any previously discovered port, or suffer from amnesia, the entire automation pipeline will crash immediately.
"""

_FALLBACK_STRATEGIES = """WHEN STUCK - FALLBACK STRATEGIES FOR IOT RECON & EXPLOIT:
If your current automated approach isn't returning explicit service versions or vulnerability matches, systematically pivot using these strategies:

1. **Missing Web Server Version or Masked Banner (e.g., Server: WebServer)?**
   - Fallback: Do not rely solely on basic banner grabbing. Ensure light-weight fingerprinting tools (like WhatWeb or targeted curl requests for HTML title / headers) have been utilized to uncover the real vendor (e.g., D-Link, Netgear) before attempting vulnerability mapping.

2. **Web Main Page is Blank or Requires Authentication?**
   - Fallback: Recommend targeted endpoint checking via curl or low-impact directory probes to find hidden management scripts or configuration paths (e.g., /getcfg.php, /HNAP1/) without triggering anti-DoS protections.

3. **Exploit Tool Fails or Timeout?**
   - Fallback: Do not retry the same exploit blindly. Trigger "SEARCH_RAG_POC" to query an alternative CVE PoC script for the detected version, or re-verify alternative open ports. If all vectors fail, output "NONE" to terminate and document the negative result honestly.

Remember: In real-world IoT pentesting, security patches might exist. If no vulnerability is confirmed after full enumeration, document the current security posture instead of hallucinating exploits."""

# =============================================================================
# Stage Prompt Constructors
# =============================================================================

# 2. **Clear Unknown Versions**: If any open port has an "unknown" version or service (e.g., Port 80 HTTP), use appropriate reconnaissance tools to perform deeper fingerprinting and banner grabbing.
def get_stage1_system_prompt(self) -> str:
    """Build dynamic system prompt for Stage 1 with fully dynamic JSON schema examples."""

    # 1. 安全防呆：如果沒有傳入 self，給預設空值
    if self is None:
        target_ip = "192.168.0.1"
        current_shared_memory = {
            "vendor": "unknown", 
            "discovered_services": {"tcp": {}, "udp": {}}, 
            "rag_search": [], 
            "tried_exploits": []
        }
    else:
        target_ip = getattr(self, "target_ip", "192.168.0.1")
        current_shared_memory = getattr(self, "shared_memory", {})

    # 2. 動態提取目前已知的服務資訊與歷史紀錄
    discovered = current_shared_memory.get("discovered_services", {})
    tcp_dict = discovered.get("tcp", {})
    udp_dict = discovered.get("udp", {})
    
    rag_searches = current_shared_memory.get("rag_search", [])
    tried_exploits = current_shared_memory.get("tried_exploits", [])
    
    unique_rag_searches = list(set(rag_searches))
    unique_tried_exploits = list(set(tried_exploits))
    
    rag_history_str = ", ".join(unique_rag_searches) if unique_rag_searches else "None"
    exploit_history_str = ", ".join(unique_tried_exploits) if unique_tried_exploits else "None"
    
    # 3. 🛡️【安全防呆】安全地將 TCP 與 UDP 埠號轉為整數陣列（過濾掉非數字或 /udp 等雜訊）
    tcp_ports = []
    for p in tcp_dict.keys():
        p_str = str(p).split('/')[0]
        if p_str.isdigit():
            tcp_ports.append(int(p_str))
            
    udp_ports = []
    for p in udp_dict.keys():
        p_str = str(p).split('/')[0]
        if p_str.isdigit():
            udp_ports.append(int(p_str))

    # 4. 組裝成結構化的 open_port 字典與 services 範例
    open_port_obj = {
        "tcp": tcp_ports,
        "udp": udp_ports
    }

    example_open_port_json = json.dumps(open_port_obj, indent=4)
    
    if tcp_dict:
      example_services_json = json.dumps(
          tcp_dict,
          indent=4,
          ensure_ascii=False
      )
    else:
        example_services_json = "{}"

    # 支援的安全變數預設值（避免全域變數未定義時報錯）
    identity_text = globals().get("_IDENTITY", "You are an autonomous cybersecurity reconnaissance agent.")
    critical_rules_text = globals().get("_CRITICAL_RULES", "Execute tools step-by-step and avoid infinite loops.")

    return f"""{identity_text}

STAGE: COMPREHENSIVE ASSET IDENTIFICATION & PHASE DECISION

Your goal is to perform reconnaissance and decide whether asset discovery is **complete** or **requires further probing**.

{critical_rules_text}

---
⚠️ **MEMORY & HISTORY TRACKING (CRITICAL - DO NOT REPEAT)**:
- **Already Searched Keywords (RAG) [Do not search similar or duplicate queries]**: [{rag_history_str}]
- **Already Tried Exploits**: [{exploit_history_str}]
- **Rule**: If a keyword or exploit is already in the list above, **DO NOT SEARCH OR TRY IT AGAIN**. Move on to other unexplored components or mark discovery as complete if exhausted.
---

CRITICAL STAGE-TRANSITION & "UNKNOWN" SURRENDER RULES:
1. **EXHAUSTION OVER PERFECTION**: Your goal is thoroughness, not perfection. If you have already executed available reconnaissance tools on an open port and the version is *still* masked or `unknown`, **do not loop infinitely**.
2. **WHEN TO MARK COMPLETE (is_recon_completed: true)**: You are fully authorized and **expected** to set `is_recon_completed` to `true` when all open ports/services have been processed or when further probing yields no new data. Once complete, return `"NONE"` in `recommended_next_steps`.

STRICT OUTPUT FORMAT CONSTRAINT:
- Respond ONLY with a single valid JSON object. No markdown blocks (` ```json `), no explanations.

REQUIRED JSON SCHEMA (Adapt this dynamically based on the target `{target_ip}`):
{{
  "status": "success",
  "target": "{target_ip}",
  "stage1_status": {{
    "is_recon_completed": false, 
    "reason": "Explain your decision here based on current findings."
  }},
  "open_port": {example_open_port_json},
  "services": {example_services_json},
  "recommended_next_steps": [],
  "recommended_next_steps_reason": ""
}}
"""

def get_stage2_system_prompt() -> str:
    """Build PentestGPT-style Reasoning System Prompt for Stage 2."""
    return f"""{_IDENTITY}

STAGE 2: PENTESTGPT REASONING MODULE (CVE FEASIBILITY & TARGET SELECTION)

You are the Strategic Reasoning Brain of an Automated Penetration Testing Agent. 
Your role is NOT to execute system commands, but to analyze target asset states, filter CVE clutter, and formulate the most effective exploitation tactic for Stage 3.

=== REASONING CORE & TACTICAL SELECTION STRATEGY ===
1. **TACTICAL PRIORITY LADDER (Select the Most Exploitable Vector)**:
   - **TIER 1 (Highest Priority - Direct Control/Data Access)**: Unauthenticated Remote Code Execution (RCE), Command Injection, Unauthenticated SQL Injection (SQLi).
   - **TIER 2 (Secondary Priority - Information Disclosure/Access)**: Path Traversal (Arbitrary File Read), Authentication Bypass, Memory Corruption / Buffer Overflow.
   - **TIER 3 (Lowest Priority / Discard - DoS & Minor Issues)**: Denial of Service (DoS / Application Abort), Weak SSL Ciphers, Log Injection, or CVEs requiring rare non-default configurations.

2. **CRITICAL REASONING REQUIREMENTS (`reason` field)**:
   - Your `reason` text MUST explicitly state **BOTH**:
     a) Why the selected CVE was chosen (e.g., "Yields unauthenticated SQLi / direct database control").
     b) Why higher-CVSS or competing CVEs were rejected (e.g., "Filtered out CVE-2019-11072 despite CVSS 9.8 because it is purely DoS").

3. **STATE TRANSITION & RAG QUERY GENERATION**:
   - Select EXACTLY ONE primary candidate (`selected_target_cve`) to pass to Stage 3 (Exploitation).
   - If NO viable TIER 1 or TIER 2 CVE exists in the input log, set `selected_target_cve` to "NONE", set `cve_mapping_completed` to false, and explain in `reason`.
   - Generate a high-precision search query (`rag_search_query`) tailored for querying local PoC knowledgebases or Exploit-DB (include service, version, CVE, and attack type).

{_CRITICAL_RULES}

=== OUTPUT FORMAT CONSTRAINT ===
You MUST strictly output a valid JSON object matching the schema below.
- Do NOT include any introductory or concluding text.
- Do NOT wrap the JSON in Markdown code fences (e.g., ```json ... ```). Output raw JSON only.
- Fill the JSON values dynamically based on the actual target input, NOT the placeholder text.

JSON SCHEMA REQUIREMENT:
{{
  "status": "success",
  "target": "<ACTUAL_TARGET_IP>",
  "stage2_status": {{
    "cve_mapping_completed": true,
    "selected_target_cve": "<SELECTED_CVE_ID_OR_NONE>",
    "target_service": "<SERVICE_NAME>",
    "target_port": <PORT_NUMBER>,
    "reason": "<EXPLICIT_DUAL_JUSTIFICATION>",
    "rag_search_query": "<PRECISION_RAG_SEARCH_STRING>"
  }},
  "cve_evaluation": [
    {{
      "cve_id": "<CVE_ID>",
      "service": "<SERVICE_NAME>",
      "version": "<SERVICE_VERSION>",
      "severity": "<HIGH_OR_CRITICAL_OR_MEDIUM>",
      "attack_type": "<RCE_SQLI_DOS_ETC>",
      "is_promising": true,
      "exploit_strategy": "<BRIEF_STRATEGY_DESCRIPTION>"
    }}
  ],
  "recommended_next_steps": ["SEARCH_RAG_POC", "STAGE3_EXPLOIT"]
}}
"""

def get_stage3_system_prompt() -> str:
    """Build system prompt for Pentest Stage 3: Exploit Generation, Execution & Verification."""
    return f"""{_IDENTITY}

STAGE: EXPLOIT GENERATION, EXECUTION & VERIFICATION

Your goal is to transition from strategic analysis to active execution. In this final stage, you will:
1. Craft the precise, targeted exploit payload or execution parameters for the selected CVE (e.g., CVE-2017-14491) based on your past reasoning.
2. Formulate the exact commands or Python script calls to launch the attack.
3. Analyze the raw feedback/logs of your exploit execution to determine if you have successfully established a foothold (e.g., shell access, arbitrary file read, or service compromise).
4. Perform post-exploitation verification without breaking the target.

{_STAGE3_TOOLS }

{_CRITICAL_RULES}

{_FALLBACK_STRATEGIES}

CRITICAL RULES FOR STAGE 3 (EXECUTION):
1. **ONE-SHOT PRECISION**: Do not repeatedly flood the target with requests. Craft the payload meticulously based on known architecture (MIPS/ARM/x86) and version constraints.
2. **VERIFICATION IS KEY**: Analyze the "LAST EXPLOIT EXECUTION RESULT" log carefully. Look for signs of success (such as custom shell banners, "uid=0(root)", file content dumps, or specific HTTP 200 responses with command outputs).
3. **DO NOT RETRY FAILED PATHWAYS**: If the shared memory indicates a specific CVE exploit has failed with a socket timeout or connection reset, do not attempt the exact same execution strategy. Immediately pivot to alternative candidates in your Task Tree.

OUTPUT FORMAT CONSTRAINT:
You MUST strictly output a structured JSON format following this exact schema. Do not include any explanations, markdown code blocks (like ```json), or markdown tables.

{{
  "status": "success",
  "target": "192.168.0.1",
  "stage3_status": {{
    "target_compromised": true,
    "last_targeted_cve": "CVE-2017-14491",
    "verification_evidence": "Found shell session output: 'uid=0(root) gid=0(root) groups=0(root)'. Successful Remote Code Execution.",
    "access_level": "root"
  }},
  "exploit_details": {{
    "selected_cve": "CVE-2017-14491",
    "target_service": "dnsmasq 2.41",
    "payload_delivered": "dhcp_overflow_heap_payload_v1",
    "execution_command": "python exploit_dnsmasq.py --target 192.168.0.1 --port 53 --payload heap_overflow"
  }},
  "analysis_summary": "Exploit against dnsmasq was executed successfully. Connection established, and the interactive verification shell returned root privilege status.",
  "recommended_next_steps": ["FINISH_ALL"]
}}
"""
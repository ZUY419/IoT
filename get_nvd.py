import requests
import sys
import json
from packaging import version as pkg_version

# ======================================
# 輔助函式 (解析與檢查)
# ======================================
def check_version_match(target_version, affected_info):
    try:
        t_ver = pkg_version.parse(target_version)
        if "start_version" in affected_info:
            start_v = pkg_version.parse(affected_info["start_version"])
            if affected_info["start_operator"] == ">=" and t_ver < start_v: return False
            if affected_info["start_operator"] == ">" and t_ver <= start_v: return False
        if "end_version" in affected_info:
            end_v = pkg_version.parse(affected_info["end_version"])
            if affected_info["end_operator"] == "<=" and t_ver > end_v: return False
            if affected_info["end_operator"] == "<" and t_ver >= end_v: return False
        return True
    except:
        return False

def search_cpe(keyword):
    url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    params = {"keywordSearch": keyword, "resultsPerPage": 1}
    try:
        response = requests.get(url, params=params, timeout=20)
        if response.status_code == 200:
            data = response.json()
            if data.get("products"):
                return data["products"][0]["cpe"]["cpeName"]
    except Exception as e:
        print(f"[!] CPE 網路請求失敗: {e}", file=sys.stderr)
    return None

def search_cve(cpe_name):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cpeName": cpe_name}
    try:
        response = requests.get(url, params=params, timeout=20)
        if response.status_code == 200:
            # 【🔥 Bug 修復】不要只拿 item["cve"]["id"]，要保留整個物件供後續解析
            return [item["cve"] for item in response.json().get("vulnerabilities", [])]
    except Exception as e:
        print(f"[!] CVE 網路請求失敗: {e}", file=sys.stderr)
    return []

def extract_configurations(cve_obj):
    affected_version = []
    cpes = []
    for config in cve_obj.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if cpe_match.get("vulnerable", False):
                    cpes.append(cpe_match.get("criteria"))
                    info = {}
                    if "versionStartIncluding" in cpe_match: info = {"start_operator": ">=", "start_version": cpe_match["versionStartIncluding"]}
                    elif "versionStartExcluding" in cpe_match: info = {"start_operator": ">", "start_version": cpe_match["versionStartExcluding"]}
                    if "versionEndIncluding" in cpe_match: info.update({"end_operator": "<=", "end_version": cpe_match["versionEndIncluding"]})
                    elif "versionEndExcluding" in cpe_match: info.update({"end_operator": "<", "end_version": cpe_match["versionEndExcluding"]})
                    affected_version.append(info)
    return {"affected_version": affected_version, "cpe": list(set(cpes))}

def extract_cvss(cve_obj):
    metrics = cve_obj.get("metrics", {})
    for key in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            metric = metrics[key][0]
            data = metric.get("cvssData", {})
            return {"version": data.get("version"), "score": data.get("baseScore"), "severity": data.get("baseSeverity"), "vector": data.get("vectorString")}
    return {}

def extract_cwe(cve_obj):
    result = []
    for weakness in cve_obj.get("weaknesses", []):
        for desc in weakness.get("description", []):
            if desc.get("lang") == "en": result.append(desc["value"])
    return result

# ======================================
# 主執行邏輯 (儲存於變數與 Markdown 轉換)
# ======================================

def get_vulnerability_data(product_name, target_version):
    vulnerability_results = []
   
    # 1. 取得 CPE 名稱
    cpe = search_cpe(f"{product_name} {target_version}")
    if not cpe:
        return vulnerability_results

    # 2. 查詢該產品的所有 CVE
    cves_data = search_cve(cpe)
   
    for cve in cves_data:
        # 解析該 CVE 的所有影響範圍
        config_data = extract_configurations(cve)
       
        # 檢查該 CVE 的任何一個影響區間是否命中 target_version
        is_really_affected = False
        
        # IoT 設備邊緣防呆：如果沒有明寫區間，但對應的原始 CPE 本身就包含了 target_version 關鍵字
        if not config_data.get("affected_version"):
            if any(target_version in c for c in config_data.get("cpe", [])):
                is_really_affected = True
        else:
            for item in config_data.get("affected_version", []):
                if check_version_match(target_version, item):
                    is_really_affected = True
                    break
       
        # 只有確認影響，才存入變數
        if is_really_affected:
            filtered_cpes = [
                c for c in config_data.get("cpe", [])
                if target_version in c
            ]
            
            result = {
                "cveID": cve.get("id"),
                "description": next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "No description available."),
                "cpe": filtered_cpes,
                "cvss": extract_cvss(cve),
                "cwe": extract_cwe(cve),
            }
            vulnerability_results.append(result)
           
    return vulnerability_results

def convert_to_markdown(results, product_name, target_version):
    """
    將 NVD 查詢結果轉為極簡格式，專門給 LLM 進行 Prompt 思考（避免 Context 爆炸與格式跑偏）
    """
    if not results:
        return f"Service {product_name} ({target_version}): No direct CVEs found in NVD."

    md = [f"NVD Vulnerabilities for {product_name} ({target_version}) [{len(results)} CVEs]:"]
    
    for item in results:
        # 相容兩種 cveID 欄位命名
        cve_id = item.get("cveID") or item.get("cve_id", "N/A")
        
        # 處理 cvss 可能是 dict 或單一數值的狀況
        cvss = item.get("cvss", {})
        if isinstance(cvss, dict):
            score = cvss.get("score", "N/A")
            severity = cvss.get("severity", "UNKNOWN")
        else:
            score = item.get("score", cvss)
            severity = item.get("severity", "UNKNOWN")
        
        # 精簡 Description：截斷過長文字，只留前 100 個字元
        raw_desc = item.get("description", "").replace("\n", " ")
        short_desc = (raw_desc[:100] + "...") if len(raw_desc) > 100 else raw_desc
        
        # 用極簡的 Bullet Point 呈現，去除了 Vector、CPE 等冗餘欄位
        md.append(f"- {cve_id} (Score: {score} {severity}): {short_desc}")
        
    return "\n".join(md)

if __name__ == "__main__":
    if len(sys.argv) >= 5:
        # 支援多種長度的命令列參數提取
        product = sys.argv[2]
        version = sys.argv[4]
    elif len(sys.argv) == 3:
        product = sys.argv[1]
        version = sys.argv[2]
    else:
        print("[Error] 參數格式不正確。", file=sys.stderr)
        sys.exit(1)

    # 1. 執行核心邏輯拿到 Python 變數資料
    raw_results = get_vulnerability_data(product, version)
    
    # 2. 將變數資料轉換為乾淨的 Markdown 格式日誌並印出
    # 當大腦使用 `current_log = self._execute_tool(action_name)` 時，拿到的就會是高可讀性的 Markdown
    markdown_output = convert_to_markdown(raw_results, product, version)
    print(markdown_output)
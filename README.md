更新後的專案程式碼
# AI Agent 模組程式碼與架構說明

本檔案由 `update_readme.py` 自動生成，僅彙整 `AI Agent` 目錄內之核心程式碼。

## 📁 資料夾: `Docker/` 

### 📄 `Docker/RAG/RAG_search.py`

```python
import argparse
import json
import os
import pickle
import re
import sys
from pathlib import Path

from dotenv import load_dotenv
import faiss
import numpy as np
import ollama

# 動態匯入 RAG_search_cve 模組
try:
    from Docker.RAG.RAG_search_cve import get_cve_details
except ImportError:
    try:
        from RAG_search_cve import get_cve_details
    except ImportError:
        from .RAG_search_cve import get_cve_details

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
VECTOR_DIR = BASE_DIR / "Vector_DB"

EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "nomic-embed-text-rag-v1")
AI_FILTER_MODEL = os.getenv("AI_FILTER_MODEL", "qwen2.5-coder:7b")
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")

client = ollama.Client(host=OLLAMA_HOST)

def load_system():
    """自動載入全量檔或分塊 FAISS Index 檔與 Metadata"""
    index_files = sorted(
        VECTOR_DIR.glob("cve*.index"),
        key=lambda x: int(re.search(r"\d+", x.stem).group())
        if re.search(r"\d+", x.stem)
        else 0,
    )
    metadata_files = sorted(
        VECTOR_DIR.glob("metadata*.pkl"),
        key=lambda x: int(re.search(r"\d+", x.stem).group())
        if re.search(r"\d+", x.stem)
        else 0,
    )

    if not index_files and (VECTOR_DIR / "cve.index").exists():
        index_files = [VECTOR_DIR / "cve.index"]
    if not metadata_files and (VECTOR_DIR / "metadata.pkl").exists():
        metadata_files = [VECTOR_DIR / "metadata.pkl"]

    if not index_files or not metadata_files:
        print(f"[!] 錯誤：在 {VECTOR_DIR} 未找到任何 index 或 metadata 檔案")
        sys.exit(1)

    systems = []
    for idx_p, meta_p in zip(index_files, metadata_files):
        idx = faiss.read_index(str(idx_p))
        with open(meta_p, "rb") as f:
            meta = pickle.load(f)
        systems.append((idx, meta))

    return systems

def analyze_single_cve(query: str, cve_data: dict) -> dict:
    """使用 LLM 判斷檢索到的 CVE 是否與使用者查詢強相關"""
    prompt = f"""
    You are a cybersecurity expert.
    User Query: "{query}"
    
    Vulnerability Data:
    {json.dumps(cve_data, indent=2, ensure_ascii=False)}
    
    Task:
    1. Determine if this CVE is relevant to the user query.
    2. Output your answer STRICTLY as a JSON object:
        {{
            "relevant": true,
            "reason": "Why it matches"
        }}
        or
        {{
            "relevant": false,
            "reason": "Why it does not match"
        }}
    3. Do not include any text outside the JSON.
    """

    try:
        response = client.chat(
            model=AI_FILTER_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a helpful assistant that outputs only valid JSON."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            options={"temperature": 0.0},
        )

        content = response["message"]["content"].strip()
        json_match = re.search(r"\{.*\}", content, re.DOTALL)
        if json_match:
            return json.loads(json_match.group())
        else:
            return {
                "relevant": False,
                "reason": "Failed to parse JSON output from AI.",
            }

    except Exception as e:
        return {"relevant": False, "reason": f"AI error: {str(e)}"}

def search_and_analyze(
    query: str, systems: list, max_ignore: int = 5, max_matches: int = 5
) -> list:
    """
    1. 產生 Query Embedding 並至 FAISS 搜尋相近向量
    2. 直接調用 RAG_search_cve.py 獲取詳細 CVE 結構化資料
    3. 經由 LLM (AI) 二次篩選相關性後傳回
    """
    query_text = f"search_query: {query}"

    try:
        query_emb = client.embed(model=EMBEDDING_MODEL, input=[query_text])[
            "embeddings"
        ]
        query_emb = np.array(query_emb, dtype="float32")
        faiss.normalize_L2(query_emb)
    except Exception as e:
        print(f"[!] Embedding 產生失敗: {e}")
        return []

    candidate_cves = []

    for index, metadata in systems:
        top_k = max_ignore * 2
        distances, indices = index.search(query_emb, top_k)

        if len(indices) > 0:
            idx_list = indices.flatten().tolist()
        else:
            continue

        for idx in idx_list:
            if isinstance(idx, int) and 0 <= idx < len(metadata):
                candidate_cves.append(metadata[idx]["cveID"])

    candidate_cves = list(dict.fromkeys(candidate_cves))

    match_cve = []
    ignore_count = 0

    for cve_id in candidate_cves:
        if ignore_count >= max_ignore or len(match_cve) >= max_matches:
            break

        # ⚡ 直接調用 RAG_search_cve.py 的 get_cve_details 獲取完整資料
        cve_detail = get_cve_details(cve_id)
        if not cve_detail.get("found"):
            continue

        cve_info = {
            "cveID": cve_id,
            "description": cve_detail.get("description", "No description provided.")
        }

        # 由 AI 過濾相關性
        result = analyze_single_cve(query, cve_info)

        if result.get("relevant"):
            match_cve.append({
                "cve_id": cve_id,
                "service": "",
                "version": "",
                "port": "",
                "severity": cve_detail.get("severity", "UNKNOWN"),
                "score": cve_detail.get("score", "N/A"),
                "cvss": cve_detail.get("cvss", "N/A"),
                "cwes": cve_detail.get("cwes", []),
                "description": cve_detail.get("description", ""),
                "PoC": cve_detail.get("PoC", []),
                "match_reason": result.get("reason", ""),
            })
            ignore_count = 0
        else:
            ignore_count += 1

    return match_cve

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RAG CVE Search Tool")
    parser.add_argument(
        "query", type=str, help="Search query (e.g., 'dnsmasq 2.41')"
    )
    args = parser.parse_args()

    systems = load_system()
    results = search_and_analyze(args.query, systems)
    print(json.dumps(results, indent=4, ensure_ascii=False))

```

### 📄 `Docker/RAG/RAG_search_cve.py`

```python
import json
import re
import textwrap
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
CVES_DIR = BASE_DIR / "Data" / "Normalization CVES"

def get_cve_file_path(cve_id: str) -> Path:
    """⚡ O(1) 常數時間精確定位 CVE JSON 檔案路徑，支援後備目錄搜尋"""
    cve_id = cve_id.strip().upper()
    parts = cve_id.split("-")
    if len(parts) == 3:
        year = parts[1]
        seq_str = parts[2]
        bucket = (seq_str[:-3] + "xxx") if len(seq_str) >= 3 else "0xxx"
        target_path = CVES_DIR / year / bucket / f"{cve_id}.json"
        if target_path.exists():
            return target_path

    # 後備目錄搜尋 (Fallback)
    fallback = list(CVES_DIR.glob(f"**/{cve_id}.json"))
    return fallback[0] if fallback else None

def get_cve_details(cve_id: str) -> dict:
    """
    精確讀取並解析單一 CVE JSON 資料，提煉出 AI Agent 滲透評估所需的所有核心資料結構 (Dict)
    """
    cve_id = cve_id.strip().upper()
    
    cve_data = {
        "cve_id": cve_id,
        "found": False,
        "description": "No description provided.",
        "severity": "UNKNOWN",
        "score": "N/A",
        "cvss": "N/A",
        "cwes": [],
        "PoC": [],
        "error": None
    }
    
    if not re.match(r'^CVE-\d{4}-\d+$', cve_id):
        cve_data["error"] = "無效的 CVE 編號格式 (應為 CVE-YYYY-XXXX)"
        return cve_data
        
    file_path = get_cve_file_path(cve_id)
    if not file_path or not file_path.exists():
        cve_data["error"] = f"找不到對應的 CVE 檔案: {cve_id}"
        return cve_data
        
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        cve_data["found"] = True
        
        # 1. 提煉 Description (描述)
        raw_desc = data.get("descriptions", "No description provided.")
        if isinstance(raw_desc, list):
            desc_items = []
            for d in raw_desc:
                if isinstance(d, dict):
                    desc_items.append(d.get("value", str(d)))
                else:
                    desc_items.append(str(d))
            raw_desc = " ".join(desc_items)
        cve_data["description"] = raw_desc
        
        # 2. 提煉 CWEs
        cwes = []
        for problem in data.get("problemTypes", []):
            if isinstance(problem, dict):
                descs = problem.get("descriptions", [])
                if isinstance(descs, list):
                    for d in descs:
                        if isinstance(d, dict) and d.get("cweID"):
                            cwes.append(d.get("cweID"))
                elif isinstance(descs, dict) and descs.get("cweID"):
                    cwes.append(descs.get("cweID"))
        cve_data["cwes"] = list(set(cwes))
        
        # 3. 提煉 CVSS 分數與 Severity
        metrics_list = data.get("metrics", [])
        if isinstance(metrics_list, list):
            for item in metrics_list:
                if isinstance(item, dict) and ("baseScore" in item or "cvssV3" in item or "cvssV2" in item):
                    score = str(item.get("baseScore") or item.get("score") or "N/A")
                    severity = str(item.get("baseSeverity") or item.get("severity") or "UNKNOWN")
                    cve_data["score"] = score
                    cve_data["cvss"] = score
                    cve_data["severity"] = severity
                    break
        elif isinstance(metrics_list, dict):
            cve_data["score"] = str(metrics_list.get("baseScore", "N/A"))
            cve_data["cvss"] = cve_data["score"]
            cve_data["severity"] = str(metrics_list.get("baseSeverity", "UNKNOWN"))

        # 4. 提煉 PoC 資訊
        poc_list = data.get("PoC", [])
        pocs = []
        if isinstance(poc_list, list):
            for poc in poc_list:
                if isinstance(poc, dict):
                    content = poc.get("poc") or poc.get("url") or str(poc)
                    if content:
                        pocs.append(content)
                elif isinstance(poc, str) and poc:
                    pocs.append(poc)
        elif isinstance(poc_list, str) and poc_list:
            pocs.append(poc_list)
        cve_data["PoC"] = pocs

    except Exception as e:
        cve_data["error"] = f"解析 JSON 檔案時發生錯誤: {str(e)}"

    return cve_data

def lookup_cve_single(cve_id: str) -> str:
    """單次查詢一個指定的 CVE 編號 (格式化傳回 JSON 字串)"""
    details = get_cve_details(cve_id)
    return json.dumps(details, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_cve = sys.argv[1]
        print(lookup_cve_single(target_cve))
    else:
        print(json.dumps({"error": "請提供欲查詢的單一 CVE 編號"}, ensure_ascii=False))

```

### 📄 `Docker/RAG/create_embedding.py`

```python
import argparse
import gc
import json
import os
import pickle
from pathlib import Path
import sys

from dotenv import load_dotenv
import faiss
import numpy as np
import ollama
from tqdm import tqdm

load_dotenv()

# --- 路徑與環境設定 ---
BASE_DIR = Path(__file__).resolve().parent
CVES_DIR = BASE_DIR / "Data" / "Normalization CVES"
VECTOR_DIR = BASE_DIR / "Vector_DB"

VECTOR_DIR.mkdir(parents=True, exist_ok=True)
CHECKPOINT_PATH = VECTOR_DIR / "checkpoint.pkl"

MODEL_NAME = os.getenv("EMBEDDING_MODEL", "nomic-embed-text-rag-v1")
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://192.168.131.1:11434")
BATCH_SIZE = 32
CHUNK_SIZE = 100000  # 每 100,000 筆寫入一個分塊檔

client = ollama.Client(host=OLLAMA_HOST)

def safe_save_pickle(filepath, data):
    """安全寫入 Pickle (避免寫入中斷導致 checkpoint 損壞)"""
    tmp_path = str(filepath) + ".tmp"
    with open(tmp_path, "wb") as f:
        pickle.dump(data, f)
    os.replace(tmp_path, filepath)

def cve_to_text(doc: dict) -> str:
    """將 CVE JSON 轉為高品質格式化純文字 (含 Nomic 前綴)"""
    desc = "\n".join(
        [d for d in doc.get("descriptions", []) if isinstance(d, str)]
    )
    vendors = ", ".join(doc.get("vendors", []))
    products = ", ".join(doc.get("products", []))

    cwes = []
    for item in doc.get("problemTypes", []):
        if isinstance(item, dict) and "descriptions" in item:
            desc_dict = item["descriptions"]
            if isinstance(desc_dict, dict):
                cwes.append(desc_dict.get("description", ""))

    versions, cpes = [], []
    for affected in doc.get("affected", []):
        if isinstance(affected, dict):
            cpes.extend(affected.get("cpes", []))
            for v in affected.get("versions", []):
                if isinstance(v, dict):
                    if v.get("version"):
                        versions.append(v["version"])
                    if v.get("lessThanOrEqual"):
                        versions.append(f"<= {v['lessThanOrEqual']}")

    scores = [
        str(m.get("baseScore", ""))
        for m in doc.get("metrics", [])
        if isinstance(m, dict) and "baseScore" in m
    ]
    severity = [
        m.get("baseSeverity", "")
        for m in doc.get("metrics", [])
        if isinstance(m, dict) and "baseSeverity" in m
    ]

    raw_text = f"""
CVE ID: {doc.get('cveID', '')}
Description: {desc}
Vendor: {vendors}
Product: {products}
Affected Version Range: {", ".join(versions)}
CPE: {", ".join(cpes)}
CWE: {", ".join(cwes)}
CVSS Score: {", ".join(scores)}
Severity: {", ".join(severity)}
Tags: {", ".join(doc.get('tags', []))}
""".strip()

    return f"search_document: {raw_text}"

def append_vectors_to_bin(chunk_idx: int, vectors: list):
    """將批次向量追加寫入二進位磁碟檔案 (極省記憶體)"""
    bin_path = VECTOR_DIR / f"temp_vectors_{chunk_idx}.bin"
    arr = np.array(vectors, dtype="float32")
    with open(bin_path, "ab") as f:
        f.write(arr.tobytes())

def save_chunk(chunk_idx: int, metadata: list):
    """從二進位檔讀取全量向量，建立 FAISS 索引與 metadata{i}.pkl"""
    bin_path = VECTOR_DIR / f"temp_vectors_{chunk_idx}.bin"
    index_path = VECTOR_DIR / f"cve{chunk_idx}.index"
    metadata_path = VECTOR_DIR / f"metadata{chunk_idx}.pkl"
    emb_path = VECTOR_DIR / f"embeddings{chunk_idx}.npy"

    if not bin_path.exists():
        print(f"[!] 錯誤：未找到二進位向量檔 {bin_path.name}")
        return

    print(
        f"\n[+] 正在將 Chunk {chunk_idx} ({len(metadata)} 筆) 轉存為 FAISS 索引..."
    )
    raw_bytes = bin_path.read_bytes()
    emb_array = np.frombuffer(raw_bytes, dtype="float32").reshape(
        len(metadata), -1
    )

    faiss.normalize_L2(emb_array)
    
    # 💡【關鍵修復】取 shape[1] 獲得向量維度整數 (如 768)
    dimension = emb_array.shape[1]
    index = faiss.IndexFlatIP(dimension)
    index.add(emb_array)

    faiss.write_index(index, str(index_path))
    np.save(emb_path, emb_array)
    safe_save_pickle(metadata_path, metadata)

    print(
        f"✅ 已成功建立分塊檔：{index_path.name} (向量數: {index.ntotal}) 與"
        f" {metadata_path.name}"
    )

    # 清理暫存檔與釋放記憶體
    if bin_path.exists():
        os.remove(bin_path)

    del emb_array, index, raw_bytes
    gc.collect()

def run_pipeline(clean_reset: bool = False):
    print(f"[+] 連線至 Windows Ollama: {OLLAMA_HOST}")
    print(f"[+] 使用模型: {MODEL_NAME}")
    print(f"[+] 切片目標: 每 {CHUNK_SIZE} 筆寫入一個 metadata.pkl / cve.index")

    if clean_reset:
        print("[!] 強制清空舊斷點與暫存檔...")
        for p in VECTOR_DIR.glob("temp_vectors_*.bin"):
            os.remove(p)
        if CHECKPOINT_PATH.exists():
            os.remove(CHECKPOINT_PATH)

    # 讀取斷點紀錄
    if CHECKPOINT_PATH.exists():
        print("[+] 讀取斷點檔案...")
        try:
            with open(CHECKPOINT_PATH, "rb") as f:
                cp = pickle.load(f)
                chunk_idx = cp.get("chunk_idx", 1)
                chunk_metadata = cp.get("chunk_metadata", [])
                processed = set(cp.get("processed", []))

                # 相容舊版：若先前斷點中有向量，轉換寫入二進位檔
                if "chunk_embeddings" in cp and cp["chunk_embeddings"]:
                    print(
                        f"[+] 檢測到舊版快取向量 ({len(cp['chunk_embeddings'])} 筆)，轉存至二進位暫存檔..."
                    )
                    append_vectors_to_bin(chunk_idx, cp["chunk_embeddings"])

            print(
                f"[+] 恢復進度：已處理 {len(processed)} 筆 | 當前 Chunk {chunk_idx} (已有"
                f" {len(chunk_metadata)} 筆未存檔資料)"
            )
        except Exception as e:
            print(f"[!] 讀取斷點檔失敗 ({e})，重新開始...")
            chunk_idx = 1
            chunk_metadata = []
            processed = set()

        # 防禦機制：若恢復進度時已有 CHUNK_SIZE 以上，先封裝寫入並清空 RAM
        if len(chunk_metadata) >= CHUNK_SIZE:
            save_chunk(chunk_idx, chunk_metadata)
            chunk_idx += 1
            chunk_metadata = []
            safe_save_pickle(CHECKPOINT_PATH, {
                "chunk_idx": chunk_idx,
                "chunk_metadata": [],
                "processed": list(processed),
            })
    else:
        chunk_idx = 1
        chunk_metadata = []
        processed = set()

    all_files = list(CVES_DIR.rglob("*.json"))
    print(f"[+] 總共找到 {len(all_files)} 個 CVE 檔案")

    if not all_files:
        print(f"[!] 錯誤：在 {CVES_DIR} 目錄下未找到 JSON 檔案！")
        sys.exit(1)

    texts_batch, docs_batch = [], []
    pbar = tqdm(total=len(all_files), desc="Building Embeddings", unit="file")
    pbar.update(len(processed))

    for file_path in all_files:
        if file_path.name in processed:
            continue

        # 1. 解析 JSON 檔（獨立例外處理）
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                doc = json.load(f)

            cve_id = doc.get("cveID")
            if not cve_id:
                processed.add(file_path.name)
                pbar.update(1)
                continue

            texts_batch.append(cve_to_text(doc))
            docs_batch.append({"cveID": cve_id, "file_name": file_path.name})

        except Exception as e:
            print(f"\n[!] 讀取或解析 JSON 檔 {file_path.name} 失敗: {e}")
            processed.add(file_path.name)  # 標記為已處理，避免死迴圈
            pbar.update(1)
            continue

        # 2. 集滿 BATCH_SIZE (32) 後批量請求 Embeddings
        if len(texts_batch) >= BATCH_SIZE:
            try:
                vectors = client.embed(model=MODEL_NAME, input=texts_batch)[
                    "embeddings"
                ]

                # 向量寫入暫存檔
                append_vectors_to_bin(chunk_idx, vectors)

                for d in docs_batch:
                    chunk_metadata.append({"cveID": d["cveID"]})
                    processed.add(d["file_name"])

                pbar.update(len(texts_batch))
                texts_batch, docs_batch = [], []

                # 寫入斷點
                safe_save_pickle(CHECKPOINT_PATH, {
                    "chunk_idx": chunk_idx,
                    "chunk_metadata": chunk_metadata,
                    "processed": list(processed),
                })

                # 達到 CHUNK_SIZE 時進行轉存與清空
                if len(chunk_metadata) >= CHUNK_SIZE:
                    save_chunk(chunk_idx, chunk_metadata)
                    chunk_idx += 1
                    chunk_metadata = []

                    safe_save_pickle(CHECKPOINT_PATH, {
                        "chunk_idx": chunk_idx,
                        "chunk_metadata": [],
                        "processed": list(processed),
                    })

            except Exception as e:
                print(f"\n[!] 產生向量批次失敗: {e}")
                texts_batch, docs_batch = [], []
                continue

    # 處理剩餘未滿 BATCH_SIZE 的資料
    if texts_batch:
        try:
            vectors = client.embed(model=MODEL_NAME, input=texts_batch)["embeddings"]
            append_vectors_to_bin(chunk_idx, vectors)
            for d in docs_batch:
                chunk_metadata.append({"cveID": d["cveID"]})
                processed.add(d["file_name"])
            pbar.update(len(texts_batch))
        except Exception as e:
            print(f"\n[!] 處理最後批次失敗: {e}")

    pbar.close()

    # 封裝最終的 Chunk
    if chunk_metadata:
        save_chunk(chunk_idx, chunk_metadata)

    if CHECKPOINT_PATH.exists():
        os.remove(CHECKPOINT_PATH)

    print("\n" + "=" * 50)
    print("🎉 所有 CVE 檔案 Processing & Embedding 順利完成！")
    print("=" * 50)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--clean", action="store_true", help="清空舊 Checkpoint 重新建庫"
    )
    args = parser.parse_args()

    run_pipeline(clean_reset=args.clean)
```

### 📄 `Docker/RAG/merge_db.py`

```python
from pathlib import Path
import pickle
import re
import faiss

BASE_DIR = Path(__file__).resolve().parent
VECTOR_DIR = BASE_DIR / "Vector_DB"

def merge_chunks(delete_sources: bool = False):
    """
    合併分塊 protection 的 metadata*.pkl 與 cve*.index 為單一的 metadata.pkl 與 cve.index
    :param delete_sources: 合併成功後是否自動刪除原始分塊檔
    """
    # 自動抓取並按數字排序 metadata1.pkl, metadata2.pkl ...
    metadata_files = sorted(
        VECTOR_DIR.glob("metadata*.pkl"),
        key=lambda x: int(re.search(r"\d+", x.stem).group())
        if re.search(r"\d+", x.stem)
        else 0,
    )
    index_files = sorted(
        VECTOR_DIR.glob("cve*.index"),
        key=lambda x: int(re.search(r"\d+", x.stem).group())
        if re.search(r"\d+", x.stem)
        else 0,
    )

    # 過濾掉如果已經存在的單一總檔
    metadata_files = [f for f in metadata_files if f.name != "metadata.pkl"]
    index_files = [f for f in index_files if f.name != "cve.index"]

    if not metadata_files or not index_files:
        print("❌ 未找到可合併的分塊檔案（metadata*.pkl / cve*.index）")
        return

    if len(metadata_files) != len(index_files):
        print(f"⚠️ 警告：metadata 分塊數量 ({len(metadata_files)}) 與 index 分塊數量 ({len(index_files)}) 不相等！")

    print(
        f"🚀 找到 {len(metadata_files)} 組分塊檔案，開始進行全量合併...\n"
    )

    # 1. 合併所有 Metadata List
    combined_metadata = []
    for mf in metadata_files:
        with open(mf, "rb") as f:
            data = pickle.load(f)
            combined_metadata.extend(data)
            print(f"  - 已載入 {mf.name}: {len(data)} 筆")

    merged_meta_path = VECTOR_DIR / "metadata.pkl"
    with open(merged_meta_path, "wb") as f:
        pickle.dump(combined_metadata, f)
    print(
        f"\n✅ [Metadata 合併完成] 總筆數: {len(combined_metadata)} 筆 ➔"
        f" {merged_meta_path.name}"
    )

    # 2. 合併所有 FAISS Index
    main_index = faiss.read_index(str(index_files[0]))
    print(
        f"\n  - 載入主索引 {index_files[0].name} (初始向量數:"
        f" {main_index.ntotal})"
    )

    for idx_file in index_files[1:]:
        sub_index = faiss.read_index(str(idx_file))
        
        # 💡【核心修復】解決 IndexFlat 沒有 merge_from 的問題
        # 從底層提取 sub_index 的向量矩陣並加入 main_index
        sub_vectors = faiss.rev_swig_ptr(
            sub_index.get_xb(), sub_index.ntotal * sub_index.d
        ).reshape(sub_index.ntotal, sub_index.d)
        
        main_index.add(sub_vectors)
        print(
            f"  - 已併入 {idx_file.name} (當前累積向量數:"
            f" {main_index.ntotal})"
        )

    merged_index_path = VECTOR_DIR / "cve.index"
    faiss.write_index(main_index, str(merged_index_path))
    print(
        f"\n✅ [FAISS Index 合併完成] 總向量數: {main_index.ntotal} ➔"
        f" {merged_index_path.name}"
    )

    # 3. 校驗兩者數量
    print("\n" + "=" * 45)
    if main_index.ntotal == len(combined_metadata):
        print("🎉 全量數據合併且 100% 長度對齊成功！")
        
        # 4. (選擇性) 清理舊分塊檔
        if delete_sources:
            print("\n[+] 正在清理舊的分塊檔案...")
            for f in metadata_files + index_files:
                f.unlink(missing_ok=True)
            print("✅ 原始分塊檔案已全數清理完畢！")
    else:
        print("⚠️ 警告：向量數量與 Metadata 筆數不吻合，請檢查！")
    print("=" * 45)

if __name__ == "__main__":
    merge_chunks(delete_sources=False)
```

### 📄 `Docker/RAG/server.py`

```python
from flask import Flask, request, jsonify
from RAG_search import search_and_analyze  

app = Flask(__name__)

@app.route('/search', methods=['POST'])
def search():
    data = request.get_json() or {}
    query = data.get('query', '')
    print(f"[RAG Server] 收到檢索請求: {query}")
    
    try:
        # 帶入 3 個必填參數 (index 與 metadata 需為 RAG 初始化載入好的全域變數)
        # 後面兩個 max_ignore=5, max_matches=5 會自動採用預設值
        result_log = search_and_analyze(query, global_index, global_metadata)
        
        return jsonify({"result": result_log})
    except Exception as e:
        print(f"[RAG Server 錯誤] {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # 監聽 0.0.0.0:8000 讓其他容器連得進來
    app.run(host='0.0.0.0', port=8000)

```

### 📄 `Docker/RAG/Data/data_normalization.py`

```python
from pathlib import Path
import json
from tqdm import tqdm
import re
from urllib.parse import urlparse
from typing import List, Dict, Optional
import os
from dotenv import load_dotenv
import requests

# =========================
# Path 設定
# =========================
folder_path = Path(__file__).resolve().parent / "CVES"
log_folder = folder_path.parent / "Error Logs"
output_folder = folder_path.parent / "Normalization CVES"

env_path = folder_path / ".env"

# 載入 .env 檔案
load_dotenv(dotenv_path=env_path)

# 透過 os.getenv 取得變數
api_key = os.getenv("API_KEY")

log_folder.mkdir(parents=True, exist_ok=True)
output_folder.mkdir(parents=True, exist_ok=True)

error_files_path = log_folder / "error_files.txt"
error_logs_path = log_folder / "error_logs.txt"
poc_path = log_folder / "poc.txt"

for file in [error_files_path, error_logs_path, poc_path]:
    with open(file, "w", encoding="utf-8") as f:
        f.write("")

# =========================
# 允許抓取的特定網站白名單與 URL 檢查機制
# =========================
ALLOWED_POC_DOMAINS = {
    "github.com",
    "raw.githubusercontent.com",
    "gist.github.com",
    "exploit-db.com",
    "packetstormsecurity.com",
    "gitlab.com"
}

URL_CACHE = {}

# def check_url_is_alive(url: str) -> bool:
#     """檢查網址是否存活（排除 404 或失效連結）"""
#     if url in URL_CACHE:
#         return URL_CACHE[url]

#     headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
#     try:
#         # 先嘗試 HEAD 請求（速度最快）
#         response = requests.head(url, headers=headers, timeout=4, allow_redirects=True)
#         if response.status_code < 400:
#             URL_CACHE[url] = True
#             return True
        
#         # 如果伺服器不支援 HEAD，改用 GET 輕量請求
#         response = requests.get(url, headers=headers, timeout=4, stream=True)
#         is_alive = response.status_code < 400
#         URL_CACHE[url] = is_alive
#         return is_alive
#     except Exception:
#         # 逾時或連線失敗均視為無效網址
#         URL_CACHE[url] = False
#         return False

# =========================
# Global Collection
# =========================
error_files = []
error_log_list = ["cveID", "descriptions", "metrics", "problemTypes", "tags", "solutions", "vendors", "products", "affected"]
rejected_count = 0
files = list(folder_path.rglob("*.json"))

# =========================
# Process CVE JSON
# =========================
for file in tqdm(files, desc="Normalizing CVE", unit="file"):
    try:
        with open(file, "r", encoding="utf-8") as f:
            data = json.load(f)

        cveMetadata = data.get("cveMetadata") or {}
        if cveMetadata.get("state") == "REJECTED":
            rejected_count += 1
            continue

        output_dict = {"cveID": cveMetadata.get("cveId", "")}
        file_vendors, file_products = set(), set()
        affected_list = []

        containers = data.get("containers") or {}
        cna = containers.get("cna") or {}

        if cna:
            output_dict["descriptions"] = [d.get("value", "") for d in (cna.get("descriptions") or [])]
            output_dict["metrics"] = [val for m in (cna.get("metrics") or []) for val in m.values() if any(k.lower().startswith("cvss") for k in m.keys())]
            output_dict["problemTypes"] = [{"descriptions": {"cweID": d.get("cweId", ""), "description": d.get("description", "")}} for pt in (cna.get("problemTypes") or []) for d in (pt.get("descriptions") or [])]
            output_dict["tags"] = [t for ref in (cna.get("references") or []) for t in (ref.get("tags") or [])]
            output_dict["solutions"] = [s.get("value", "") for s in (cna.get("solutions") or [])]

            # Affected
            for affected in (cna.get("affected") or []):
                v, p = affected.get("vendor", ""), affected.get("product", "")
                if v: file_vendors.add(v)
                if p: file_products.add(p)
                affected_list.append({"vendor": v, "product": p, "cpes": affected.get("cpes") or [], "versions": affected.get("versions") or []})

            # Filtered PoC: 僅限白名單網域 且 檢查不是 404（存活）才放入 PoC 清單
            filtered_poc_urls = []
            for ref in (cna.get("references") or []):
                url = ref.get("url")
                if not url:
                    continue
                
                parsed = urlparse(url.lower())
                domain = parsed.netloc.replace("www.", "")
                
                # 1. 檢查是否符合特定網站白名單
                is_allowed_domain = any(allowed in domain for allowed in ALLOWED_POC_DOMAINS)
                
                if is_allowed_domain:
                    filtered_poc_urls.append(url)
            
            output_dict["PoC"] = filtered_poc_urls

        # ADP
        for adp in (containers.get("adp") or []):
            for affected in (adp.get("affected") or []):
                v, p = affected.get("vendor", ""), affected.get("product", "")
                if v: file_vendors.add(v)
                if p: file_products.add(p)
                affected_list.append({"vendor": v, "product": p, "cpes": affected.get("cpes") or [], "versions": affected.get("versions") or []})

        # 合併集合 (使用 set 去除重複值)
        final_vendors = set(file_vendors)
        final_products = set(file_products)

        # 更新字典 (確保轉回 list)
        output_dict.update({
            "vendors": sorted(list(final_vendors)), 
            "products": sorted(list(final_products)), 
            "affected": affected_list
        })

        output_file = output_folder / file.relative_to(folder_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(output_dict, f, ensure_ascii=False, indent=4)

        empty_fields = [f for f in error_log_list if not output_dict.get(f)]
        if empty_fields:
            with open(error_logs_path, "a", encoding="utf-8") as f:
                f.write(f"{file.name} = {empty_fields}\n")

    except Exception as e:
        error_files.append(f"---- {file} ----\nerror = {e}\n\n")

if error_files:
    with open(error_files_path, "w", encoding="utf-8") as f:
        f.writelines(error_files)

print(f"\n{'='*10} Normalization Summary {'='*10}")
print(f"Total files : {len(files)}")
print(f"Rejected    : {rejected_count}")
print(f"Errors      : {len(error_files)}")
```

### 📄 `Docker/RAG/Data/get_PoC.py`

```python
import json
import time
import requests
from bs4 import BeautifulSoup
from tqdm import tqdm
from pathlib import Path

folder_path = Path(__file__).resolve().parent
output_path = folder_path / "PoC_content.txt"
CVE_files = folder_path / "Normalization CVES"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

SECTION_KEYWORDS = {
    "poc": [
        "proof of concept", "poc", "proof", "exploit", 
        "reproduction", "steps to reproduce", "example request", "payload"
    ]
}

def classify_heading(text):
    text = text.lower().strip()
    for v in SECTION_KEYWORDS["poc"]:
        if v in text:
            return "poc"
    return None

def extract_poc_section(soup):
    poc_text = ""
    current = False
    for element in soup.find_all(["h1", "h2", "h3", "h4", "p", "pre", "li"]):
        text = element.get_text("\n", strip=True)
        if not text:
            continue
        if element.name in ["h1", "h2", "h3", "h4"]:
            if classify_heading(text):
                current = True
                continue
            else:
                current = False
        if current:
            poc_text += text + "\n"
    return poc_text.strip()

def parse_advisory(session, url):
    max_retries = 3
    backoff_factor = 2  

    # 1. 🔑 支援 Exploit-DB 網址，直接轉為下載原始攻擊腳本
    if "exploit-db.com/exploits/" in url:
        parts = url.rstrip("/").split("/")
        if parts[-1].isdigit():
            exploit_id = parts[-1]
            download_url = f"https://www.exploit-db.com/download/{exploit_id}"
            for attempt in range(max_retries):
                try:
                    res = session.get(download_url, headers=HEADERS, timeout=30)
                    if res.status_code == 429:
                        time.sleep(backoff_factor ** (attempt + 1))
                        continue
                    res.raise_for_status()
                    return {
                        "url": url,
                        "title": f"Exploit-DB Exploit #{exploit_id}",
                        "poc": res.text.strip()
                    }
                except requests.exceptions.RequestException:
                    if attempt == max_retries - 1:
                        break
                    time.sleep(2)

    # 一般網頁的重試請求邏輯
    for attempt in range(max_retries):
        try:
            response = session.get(url, headers=HEADERS, timeout=30)
            
            if response.status_code == 429:
                sleep_time = backoff_factor ** (attempt + 1)
                tqdm.write(f"[!] 遇到 429 限制 ({url})，正在進行第 {attempt + 1} 次重試，等待 {sleep_time} 秒...")
                time.sleep(sleep_time)
                continue

            response.raise_for_status()
            break
        except requests.exceptions.RequestException as e:
            if attempt == max_retries - 1:
                return {"error": str(e)}
            time.sleep(2)
    else:
        return {"error": "429 Too Many Requests: 重試次數耗盡"}

    # 2. 支援 .patch、.diff 或 .driff 檔案直接當作 PoC 收錄
    if url.endswith(".patch") or url.endswith(".diff") or url.endswith(".driff"):
        return {
            "url": url,
            "title": "GitHub Commit Patch / Diff",
            "poc": response.text.strip()
        }

    # 3. 一般 HTML 網頁解析
    soup = BeautifulSoup(response.text, "html.parser")
    for tag in soup(["script", "style", "svg", "nav", "footer", "header"]):
        tag.decompose()

    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    poc_content = extract_poc_section(soup)

    return {
        "url": url,
        "title": title,
        "poc": poc_content
    }

if __name__ == "__main__":
    files = list(CVE_files.rglob("*.json"))

    with requests.Session() as session:
        for file in tqdm(files, desc="Normalizing CVE", unit="file"):
            try:
                with open(file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                urls = data.get("PoC", [])
                references = data.get("references", [])
                
                if not urls and not references:
                    continue

                poc_list = []
                references_list = []
                has_updated = False

                for item in urls:
                    if isinstance(item, dict):
                        if item.get("poc"):
                            poc_list.append(item)
                        else:
                            if "url" in item:
                                references_list.append(item["url"])
                        continue

                    if type(item) is not str:
                        continue
                    if not (item.startswith("http://") or item.startswith("https://")):
                        continue

                    url = item
                    tqdm.write(f"[*] 正在檢查網址: {url}")
                    result = parse_advisory(session, url)

                    if "error" in result:
                        err_msg = result["error"]
                        if "404" in err_msg:
                            tqdm.write(f"[!] 發現 404 錯誤，已自動刪除此網址: {url}")
                        else:
                            tqdm.write(f"[!] 請求失敗 ({err_msg})，已自動刪除此網址: {url}")
                        has_updated = True
                        continue

                    if result.get("poc"):
                        tqdm.write("[+] 發現明確的 PoC 內容（或 Exploit-DB/Patch），收錄至 PoC 欄位！")
                        poc_list.append(result)
                        has_updated = True
                    else:
                        tqdm.write("[-] 無明確 PoC 標題或內容，歸類至 references 欄位。")
                        references_list.append(url)
                        has_updated = True

                    time.sleep(1.5)

                for ref_url in references:
                    if isinstance(ref_url, str) and (ref_url.startswith("http://") or ref_url.startswith("https://")):
                        if ref_url not in references_list and ref_url not in [p.get("url") for p in poc_list]:
                            references_list.append(ref_url)

                data["PoC"] = poc_list
                data["references"] = references_list

                if has_updated:
                    with open(file, "w", encoding="utf-8") as f:
                        f.write(json.dumps(data, indent=4, ensure_ascii=False))

            except Exception as e:
                tqdm.write(f"---- {file} ----\nerror = {e}\n\n")
        
    print(f"\n[*] 處理完成！所有 JSON 檔案已更新分類。")
```

### 📄 `Docker/RAG/Data/get_exploitdb_poc_links.py`

```python
import pandas as pd
import json
import re
from pathlib import Path
from tqdm import tqdm

def update_all_poc():
    # 設定路徑
    folder_path = Path(__file__).resolve().parent
    normal_dir = folder_path / "Normalization CVES"
    csv_path = folder_path / "exploitdb" / "files_exploits.csv"

    if not normal_dir.exists() or not csv_path.exists():
        print("[!] 錯誤: 找不到路徑")
        return

    # 1. 映射 CSV
    print(f"[+] 正在解析 CSV: {csv_path}")
    df = pd.read_csv(csv_path)
    lookup_dict = {}
    cve_pattern = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

    for _, row in tqdm(df.iterrows(), total=len(df), desc="Mapping CSV"):
        codes = str(row['codes'])
        if codes == 'nan': continue
        found_cves = cve_pattern.findall(codes)
        for cve in found_cves:
            cve = cve.upper()
            link = f"https://www.exploit-db.com/exploits/{row['id']}"
            if cve not in lookup_dict: lookup_dict[cve] = []
            if link not in lookup_dict[cve]: lookup_dict[cve].append(link)

    # 2. 更新 JSON 並記錄變更
    json_files = list(normal_dir.rglob("*.json"))
    updated_cves = [] # 用來存被更新的 CVE ID
    
    print("[+] 開始更新 JSON 並追蹤變更...")
    for file_path in tqdm(json_files, desc="Updating JSON"):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            cve_id = data.get("cveID")
            if not cve_id: continue

            poc_links = lookup_dict.get(cve_id, [])
            
            # 只有當確實有連結可以填入時才更新
            if poc_links:
                for link in poc_links:
                    data["PoC"].append(link)
                updated_cves.append(cve_id) # 紀錄這個 CVE 被更動了

                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, indent=4)
                    
        except Exception as e:
            print(f"\n[!] 處理 {file_path.name} 失敗: {e}")

    # 3. 輸出紀錄
    print(f"\n[+] 全部完成！共更新 {len(updated_cves)} 個檔案。")
    
    # 將被更新的列表存檔
    log_path = folder_path / "updated_cves.txt"
    with open(log_path, "w", encoding="utf-8") as f:
        for cve in updated_cves:
            f.write(f"{cve}\n")
    print(f"[+] 被更新的 CVE 清單已存至: {log_path}")

if __name__ == "__main__":
    update_all_poc()
```

### 📄 `Docker/ai/langchain/get_nvd.py`

```python
# Docker/ai/langchain/get_nvd.py
import urllib.request
import urllib.parse
import json
import ssl

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def get_vulnerability_data(product_name: str, target_version: str = "") -> list:
    """
    透過 NVD API v2 線上查詢特定產品與版本的 CVE 漏洞資料。
    安全處理 list/dict 解析，避免 'list indices must be integers or slices, not str' 錯誤。
    """
    query_str = f"{product_name} {target_version}".strip()
    encoded_query = urllib.parse.quote(query_str)
    url = f"{NVD_API_URL}?keywordSearch={encoded_query}"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PentestAgent/2.0"
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    results = []

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15, context=ctx) as response:
            if response.status != 200:
                print(f"[!] NVD API 回應異常狀態碼: {response.status}")
                return []
            
            raw_data = response.read().decode("utf-8", errors="ignore")
            data = json.loads(raw_data)

        if not isinstance(data, dict):
            print("[!] NVD 回傳資料格式非 dict 物件")
            return []

        vulnerabilities = data.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            print(f"[!] NVD vulnerabilities 欄位非 list 類型: {type(vulnerabilities)}")
            return []

        for item in vulnerabilities:
            if not isinstance(item, dict):
                continue
            
            cve_obj = item.get("cve", {})
            if not isinstance(cve_obj, dict):
                continue

            cve_id = cve_obj.get("id", "N/A")

            # 提煉描述
            descriptions = cve_obj.get("descriptions", [])
            cve_desc = "No description available."
            if isinstance(descriptions, list):
                for desc in descriptions:
                    if isinstance(desc, dict) and desc.get("lang") == "en":
                        cve_desc = desc.get("value", cve_desc)
                        break
                    elif isinstance(desc, dict) and "value" in desc:
                        cve_desc = desc.get("value", cve_desc)

            # 提煉 CVSS 分數與 Severity
            metrics = cve_obj.get("metrics", {})
            score = "N/A"
            severity = "UNKNOWN"

            if isinstance(metrics, dict):
                metric_keys = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]
                for key in metric_keys:
                    metric_list = metrics.get(key, [])
                    if isinstance(metric_list, list) and len(metric_list) > 0:
                        m_item = metric_list[0]
                        if isinstance(m_item, dict):
                            cvss_data = m_item.get("cvssData", {})
                            if isinstance(cvss_data, dict):
                                score = cvss_data.get("baseScore", score)
                                severity = cvss_data.get("baseSeverity", m_item.get("baseSeverity", severity))
                                break

            results.append({
                "cveID": cve_id,
                "cve_id": cve_id,
                "description": cve_desc,
                "score": str(score),
                "severity": str(severity),
                "cvss": {"score": str(score), "severity": str(severity)}
            })

    except Exception as e:
        print(f"[!] NVD 網路請求或解析失敗: {e}")
        return []

    return results

def convert_to_markdown(vuln_results: list, product_name: str, target_version: str) -> str:
    """將漏洞查詢結果格式化為 Markdown 摘要表格與列表"""
    if not vuln_results or not isinstance(vuln_results, list):
        return f"（NVD 查詢結果：線上 NVD 資料庫中未找到與 `{product_name} {target_version}` 相關的已知漏洞。）"

    lines = [f"### 🌐 NVD 線上漏洞檢索結果 ({product_name} {target_version})"]
    lines.append(f"共找到 {len(vuln_results)} 筆匹配的 CVE 漏洞：\n")

    for idx, item in enumerate(vuln_results[:10], 1):
        if not isinstance(item, dict):
            continue
        cve_id = item.get("cveID") or item.get("cve_id", "N/A")
        score = item.get("score", "N/A")
        severity = item.get("severity", "UNKNOWN")
        desc = item.get("description", "")
        if len(desc) > 150:
            desc = desc[:150] + "..."

        lines.append(f"{idx}. **{cve_id}** [CVSS {score} - {severity}]")
        lines.append(f"   - **描述**: {desc}")

    return "\n".join(lines)

```

### 📄 `Docker/ai/langchain/main.py`

```python
# Docker/ai/langchain/main.py

import json
import os
from dotenv import load_dotenv

import util
from config.logging import log_info
from tools import PentestToolbox
from tool_config import dispatch_tool, get_langchain_tools
import ai.prompt as prompt
from ai.reasoning import ReasoningModule
from ai.generation import GenerationModule
from ai.parsing import ParsingModule
from ai.task_tree import PentestTaskTree, TaskStatus

load_dotenv()

TARGET_IP = os.getenv("TARGET_IP", prompt.TARGET_IP)

class PentestBox:

    def __init__(self, reset_memory: bool = True):
        self.turn = 0
        self.current_state = 1  # 1: 資產偵察, 2: 漏洞評估/攻擊
        self.net_tools = PentestToolbox(TARGET_IP)

        # 一開始初始化 / 重置 Share Memory (LangChain State Store)
        self.memory_store = util.LangChainPentestMemory(target_ip=TARGET_IP, reset=reset_memory)

        # 初始化三模組 Agent AI 架構
        self.reasoning_module = ReasoningModule()
        self.generation_module = GenerationModule()
        self.parsing_module = ParsingModule()

        # 封裝 LangChain StructuredTools 供擴充元件使用
        self.langchain_tools = get_langchain_tools(self.net_tools)

        self.share_memory = util.get_share_memory()
        log_info.info("✨ [Share Memory] 成功在程式啟動一開始完成初始化！")
        log_info.share_memory(self.share_memory)

    def exec_tool(self, tool_obj):
        if not tool_obj or not isinstance(tool_obj, dict):
            return "（無可執行的指令或工具）"

        tool_name = tool_obj.get("tool_name", tool_obj.get("name", "")).strip()
        argument = tool_obj.get("argument", tool_obj.get("parameters", {}))

        cmd_str = ""
        if isinstance(argument, dict):
            cmd_str = argument.get(
                "cmd",
                argument.get(
                    "command",
                    argument.get("url", argument.get("query", ""))
                )
            )
        elif isinstance(argument, str):
            cmd_str = argument
        cmd_str = cmd_str.strip() if isinstance(cmd_str, str) else ""

        # 1. Nmap 阻擋防護
        if "nmap" in cmd_str.lower() or "nmap" in tool_name.lower():
            log_info.warn("⚠️ [ExecTool 攔截] AI 試圖呼叫 Nmap，已自動阻擋！")
            return (
                "（系統提示：Nmap 基礎掃描已由固定 SOP"
                " 完成。請勿重複使用 Nmap，請改用 analyze_web_page, rag_search_cve"
                " 等專用工具。）"
            )

        # 2. 針對 rag_search_cve 重複呼叫的【硬性自動轉譯降級 (Hard Fallback)】
        if tool_name == "rag_search_cve":
            query_str = ""
            if isinstance(argument, dict):
                query_str = argument.get("query", argument.get("cmd", ""))
            elif isinstance(argument, str):
                query_str = argument
            query_str = query_str.strip()

            searched_queries = self.share_memory.get("searched_rag_queries", [])
            if query_str and query_str.lower() in [q.lower() for q in searched_queries]:
                log_info.warn(
                    f"⚠️ [Hard Fallback 觸發] AI 嘗試對已檢索過的關鍵字 `{query_str}`"
                    " 再次呼叫 rag_search_cve！程式自動轉譯降級為 analyze_web_page。"
                )
                tool_obj["tool_name"] = "analyze_web_page"
                tool_obj["argument"] = {"url": f"http://{TARGET_IP}"}
                tool_name = "analyze_web_page"
                argument = {"url": f"http://{TARGET_IP}"}

        # 3. Overseer Repetition Guard
        history = self.share_memory.get("tool_history", [])
        recent_cmds = []
        for h in history[-4:]:
            t_arg = h.get("tool", {}).get("argument", {})
            if isinstance(t_arg, dict):
                recent_cmds.append(
                    t_arg.get("cmd", t_arg.get("url", t_arg.get("query", "")))
                )
            elif isinstance(t_arg, str):
                recent_cmds.append(t_arg)

        if cmd_str and recent_cmds.count(cmd_str) >= 2:
            log_info.warn(f"⚠️ [Overseer 攔截] 檢測到重複指令: `{cmd_str}`")
            return (
                f"（系統提示 [Overseer Guard]：指令 `{cmd_str}` 已重複執行多次且無新進展！"
                "請勿再重複發送該命令。請換用其他工具（如 analyze_web_page 頁面分析），或若已掌握資訊，請設定 'stage_completed': true"
                " 結束本階段。）"
            )

        return dispatch_tool(self.net_tools, tool_name, argument)

    def run_state_1_sop(self):
        log_info.info(
            "⚙️ [固定 SOP] 開始執行第一階段全 TCP 與 UDP 自動探測..."
        )
        self.net_tools.nmap_scan_tcp()
        self.net_tools.nmap_scan_udp()

    def pentestPipeLine(self):
        log_info.info("🚀 PentestGPT v2 (LangChain + EGATS + TDA) 滲透測試 Agent 正式啟動！")
        self.run_state_1_sop()

        last_observation = prompt.INITIAL_USER_PROMPT

        while True:
            try:
                self.turn += 1
                log_info.info(
                    f"\n=== 第 {self.turn} 輪 | 階段 {self.current_state} (PentestGPT v2"
                    " 三模組解耦推演) ==="
                )

                # -------------------------------------------------------------
                # 步驟 1: 推理與決策模組 (Reasoning Module)
                # -------------------------------------------------------------
                self.share_memory = util.get_share_memory()
                reasoning_res = self.reasoning_module.run(
                    self.share_memory, last_observation
                )

                decided_task = reasoning_res.get("decided_task", "分析目標開放服務")
                stage_completed = reasoning_res.get("stage_completed", False)

                if stage_completed:
                    log_info.info("✅ Reasoning 模組判定當前階段任務已完成！")
                    if self.current_state == 1:
                        self.current_state = 2
                        log_info.info(
                            "進入第二階段：漏洞評估與攻擊利用 (Stage 2 Exploit)"
                        )
                        last_observation = (
                            "進入第二階段漏洞評估，請檢視 Share Memory 中 web_footprints"
                            " 及 ports，展開針對性驗證。"
                        )
                        continue
                    else:
                        log_info.info("🏁 全流程滲透測試安全結束。")
                        break

                # -------------------------------------------------------------
                # 步驟 2: 指令生成模組 (Generation Module)
                # -------------------------------------------------------------
                tool_obj = self.generation_module.run(
                    decided_task, self.share_memory
                )

                # -------------------------------------------------------------
                # 步驟 3: 工具執行 (Execution)
                # -------------------------------------------------------------
                raw_exec_log = self.exec_tool(tool_obj)
                log_info.info(
                    f"⚙️ 原始執行結果 Log (長度 {len(raw_exec_log)} 字元):\n{raw_exec_log[:200]}..."
                )

                # -------------------------------------------------------------
                # 步驟 4: 結果解析與壓縮模組 (Parsing Module)
                # -------------------------------------------------------------
                tool_name = tool_obj.get("tool_name", "execute_cli")
                argument = tool_obj.get("argument", {})
                parsed_res = self.parsing_module.run(
                    tool_name, argument, raw_exec_log
                )

                condensed_summary = parsed_res.get("summary", raw_exec_log[:300])
                new_evidence = parsed_res.get("new_evidence_found", False)

                # -------------------------------------------------------------
                # 步驟 5: TDA (Task Difficulty Assessment) 嘗試反饋與 PTT 同步
                # -------------------------------------------------------------
                self.share_memory = util.get_share_memory()
                if "task_tree" in self.share_memory and isinstance(self.share_memory["task_tree"], dict):
                    try:
                        tree = PentestTaskTree.from_dict(self.share_memory["task_tree"])
                        active_node_id = None
                        for nid, nd in tree.nodes.items():
                            if nd.status in [TaskStatus.TO_DO, TaskStatus.IN_PROGRESS] and (nd.title in decided_task or decided_task in nd.title):
                                active_node_id = nid
                                break
                        if not active_node_id and tree.root_ids:
                            active_node_id = tree.root_ids[0]

                        if active_node_id:
                            tda_status = tree.record_attempt(active_node_id, success=True, new_evidence_found=new_evidence)
                            if tda_status == TaskStatus.PRUNED:
                                log_info.warn(f"⚠️ [TDA 自動剪枝觸發] 節點 `{active_node_id}` 連續嘗試缺乏新證據，自動剪枝避開！")

                        self.share_memory["task_tree"] = tree.to_dict()
                        util.update_share_memory(self.share_memory)
                    except Exception as te:
                        log_info.error(f"❌ [TDA 反饋同步失敗]: {te}")

                # -------------------------------------------------------------
                # 步驟 6: 狀態持久化 (LangChain Memory Save Context)
                # -------------------------------------------------------------
                self.memory_store.save_context(
                    inputs={"decided_task": decided_task, "tool": tool_obj},
                    outputs={
                        "summary": condensed_summary,
                        "extracted_facts": parsed_res.get("extracted_facts", {}),
                        "new_evidence_found": new_evidence,
                    }
                )

                self.share_memory = util.get_share_memory()
                last_observation = (
                    f"【上輪執行任務】: {decided_task}\n"
                    f"【呼叫工具】: {tool_name}\n"
                    f"【提煉摘要】: {condensed_summary}"
                )
                self.share_memory["current_observation"] = last_observation
                log_info.share_memory(self.share_memory)

            except KeyboardInterrupt:
                log_info.warn("\n[!] 使用者手動中斷滲透測試。")
                break
            except Exception as e:
                log_info.error(f"三模組管道執行異常: {e}")
                break

if __name__ == "__main__":
    pentest = PentestBox()
    pentest.pentestPipeLine()

```

### 📄 `Docker/ai/langchain/tool_config.py`

```python
# Docker/ai/langchain/tool_config.py

import json
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from config.logging import log_info

# =====================================================================
# 1. Pydantic 結構化 Schemas (LangChain & Pydantic Standard)
# =====================================================================

class ReasoningResponse(BaseModel):
    thought: str = Field(description="隊長分析全局 PTT 與 Share Memory 的思考過程")
    decided_task: str = Field(description="決定的下一個高階子任務描述")
    stage_completed: bool = Field(default=False, description="當前階段任務是否已全部完成")

class ToolCallArgument(BaseModel):
    cmd: Optional[str] = Field(default="", description="Linux CLI 指令")
    url: Optional[str] = Field(default="", description="目標網址")
    query: Optional[str] = Field(default="", description="搜尋關鍵字")

class ToolCall(BaseModel):
    tool_name: str = Field(description="工具名稱: analyze_web_page, rag_search_cve, nvd_search_cve, execute_cli")
    argument: ToolCallArgument = Field(default_factory=ToolCallArgument, description="工具調用參數")

class GenerationResponse(BaseModel):
    thought: str = Field(description="將子任務轉換為工具/指令的思考推導 (CoT)")
    tool: ToolCall = Field(description="具體工具與參數物件")

class ParsingResponse(BaseModel):
    summary: str = Field(description="從原始 Log 提煉出的 3-5 句精準安全摘要")
    extracted_facts: Dict[str, Any] = Field(default_factory=dict, description="從 Log 提取的結構化資訊 (如 ports, cves, urls)")
    new_evidence_found: bool = Field(default=False, description="本次執行是否發現新的資產、端點或漏洞情報 (供 TDA 剪枝判斷)")
    status: str = Field(default="success", description="執行結果狀態 (success / failed / partial)")

class IoTVendorInfo(BaseModel):
    name: str = Field(description="IoT 設備廠商名稱，例如 D-Link, Netgear")
    description: str = Field(description="廠商背景與說明")

class IoTDeviceCategory(BaseModel):
    category: str = Field(description="設備種類，例如 Wireless Router, IP Camera")
    description: str = Field(description="設備類型的用途說明")

class WebPageInvestigation(BaseModel):
    url: str = Field(description="頁面檔名或 URL，例如 login_real.htm, wizard_default.htm")
    description: str = Field(description="該頁面的用途、轉向機制與潛在攻擊面說明")

class AdditionalNotes(BaseModel):
    script_functionality: Optional[str] = Field(default="", description="頁面中 JavaScript 函數用途 (如 get_login_info, get_settings_xml)")
    charset: Optional[str] = Field(default="UTF-8", description="網頁字元集編碼，如 UTF-8")

class IoTWebAnalysisResponse(BaseModel):
    iot_vendor: IoTVendorInfo
    device_type: IoTDeviceCategory
    web_pages_for_deeper_investigation: List[WebPageInvestigation]
    additional_notes: Optional[AdditionalNotes] = None

# 相容舊版 Dict Schema，供原本 call_ollama_json 呼叫使用
REASONING_RESPONSE_SCHEMA = ReasoningResponse.model_json_schema()
GENERATION_RESPONSE_SCHEMA = GenerationResponse.model_json_schema()
PARSING_RESPONSE_SCHEMA = ParsingResponse.model_json_schema()
IOT_WEB_ANALYSIS_SCHEMA = IoTWebAnalysisResponse.model_json_schema()

# =====================================================================
# 2. LangChain 工具調用分發器 (LangChain Tool Dispatcher)
# =====================================================================

def dispatch_tool(toolbox_instance, tool_name: str, arguments: dict) -> str:
    tool_name = tool_name.strip() if tool_name else ""

    if not tool_name:
        return "（提示：LLM 未指定任何工具名稱）"

    # 使用 Pydantic 模型進行輸入參數驗證，防止類型錯亂
    if isinstance(arguments, dict):
        try:
            validated_arg = ToolCallArgument(**arguments)
        except Exception:
            validated_arg = ToolCallArgument(cmd=str(arguments))
    else:
        validated_arg = ToolCallArgument(cmd=str(arguments))

    if tool_name == "analyze_web_page":
        log_info.info("🛠️ [LangChain Dispatcher] 觸發 analyze_web_page...")
        target_url = validated_arg.url or validated_arg.cmd or ""
        return toolbox_instance.analyze_web_page(target_url)

    elif tool_name == "rag_search_cve":
        log_info.info("🛠️ [LangChain Dispatcher] 觸發 rag_search_cve...")
        target_query = validated_arg.query or validated_arg.cmd or ""
        return toolbox_instance.rag_search_cve(target_query)

    elif tool_name == "nvd_search_cve":
        log_info.info("🛠️ [LangChain Dispatcher] 觸發 nvd_search_cve...")
        target_query = validated_arg.query or validated_arg.cmd or ""
        return toolbox_instance.nvd_search_cve(target_query)

    elif tool_name in ["execute_cli", "command"]:
        cmd_str = validated_arg.cmd or ""
        if not cmd_str:
            return "（提示：未提供具體的 CLI 指令）"
        return toolbox_instance.execute_cli(cmd_str)

    elif tool_name == "nmap_scan_tcp":
        log_info.info("🛠️ [LangChain Dispatcher] 觸發 nmap_scan_tcp...")
        tcp_results = toolbox_instance.nmap_scan_tcp()
        return f"（TCP 掃描完成，已獲取 {len(tcp_results)} 個開放埠，結果已更新至 Share Memory）"

    elif tool_name == "nmap_scan_udp":
        log_info.info("🛠️ [LangChain Dispatcher] 觸發 nmap_scan_udp...")
        udp_results = toolbox_instance.nmap_scan_udp()
        return f"（UDP 掃描完成，已獲取 {len(udp_results)} 個開放埠，結果已更新至 Share Memory）"

    else:
        log_info.warn(f"⚠️ [LangChain Dispatcher] 未知的工具名稱: {tool_name}，嘗試回退至 CLI 命令執行...")
        cmd_str = validated_arg.cmd or str(arguments)
        if cmd_str:
            return toolbox_instance.execute_cli(cmd_str)
        return f"（錯誤：無法識別的工具名稱 `{tool_name}`）"

# =====================================================================
# 3. LangChain Structured Tools 封裝工廠
# =====================================================================

def get_langchain_tools(toolbox_instance) -> List[Any]:
    """
    將 PentestToolbox 方法轉換為 LangChain 官方 StructuredTool 物件
    """
    try:
        from langchain_core.tools import StructuredTool

        tools = [
            StructuredTool.from_function(
                func=toolbox_instance.analyze_web_page,
                name="analyze_web_page",
                description="分析 Web 頁面 HTML、表單欄位、隱藏敏感 URL 與 IoT 資產類型",
            ),
            StructuredTool.from_function(
                func=toolbox_instance.rag_search_cve,
                name="rag_search_cve",
                description="本地 FAISS 向量資料庫檢索 CVE 與 PoC 腳本",
            ),
            StructuredTool.from_function(
                func=toolbox_instance.nvd_search_cve,
                name="nvd_search_cve",
                description="線上 NVD API 查詢最新 CVE 與 CVSS 評分",
            ),
            StructuredTool.from_function(
                func=toolbox_instance.execute_cli,
                name="execute_cli",
                description="執行具體 Linux CLI 滲透測試指令與 PoC 驗證腳本",
            ),
        ]
        return tools
    except ImportError:
        log_info.warn("langchain_core 未安裝，跳過 StructuredTool 封裝")
        return []

```

### 📄 `Docker/ai/langchain/tools.py`

```python
# Docker/ai/langchain/tools.py
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import urllib.request
from config.logging import log_info
import util

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# 工具與系統 apt 套件對照表
TOOL_PACKAGE_MAP = {
    "dirb": "dirb",
    "gobuster": "gobuster",
    "dig": "dnsutils",
    "nslookup": "dnsutils",
    "nmap": "nmap",
    "hydra": "hydra",
    "nc": "netcat-openbsd",
    "netcat": "netcat-openbsd",
    "curl": "curl",
    "nikto": "nikto",
}

class PentestToolbox:
    _rag_systems = None

    def __init__(self, target_ip: str):
        self.target_ip = target_ip

    @classmethod
    def _init_rag_system(cls):
        """延遲載入 RAG FAISS 向量索引資料庫"""
        if cls._rag_systems is None:
            try:
                from Docker.RAG.RAG_search import load_system
                cls._rag_systems = load_system()
                log_info.info("✅ [RAG 模組] FAISS 向量資料庫與 Metadata 成功載入！")
            except Exception as e:
                log_info.error(f"❌ [RAG 模組] 載入 FAISS 資料庫失敗: {e}")

    @staticmethod
    def ensure_tool_installed(cmd_name) -> bool:
        """自動檢測工具是否存在，若缺失則自動呼叫 apt-get 安裝"""
        if isinstance(cmd_name, list):
            cmd_name = cmd_name if cmd_name else ""
        elif not isinstance(cmd_name, str):
            cmd_name = str(cmd_name)

        if not cmd_name or shutil.which(cmd_name) is not None:
            return True

        package_name = TOOL_PACKAGE_MAP.get(cmd_name, cmd_name)
        log_info.warn(f"⚠️ 檢測到系統缺乏工具 `{cmd_name}`，嘗試自動安裝套件 `{package_name}`...")

        try:
            install_cmd = f"sudo apt-get update -qq && sudo apt-get install -y {package_name}"
            res = subprocess.run(install_cmd, shell=True, capture_output=True, text=True, timeout=120)

            if res.returncode == 0 and shutil.which(cmd_name) is not None:
                log_info.info(f"✅ 自動安裝工具 `{cmd_name}` 成功！")
                return True
            else:
                log_info.error(f"❌ 自動安裝 `{package_name}` 失敗:\n{res.stderr}")
                return False
        except Exception as e:
            log_info.error(f"❌ 安裝套件發生例外: {e}")
            return False

    def nmap_scan_tcp(self, sensitive_ports: set = None) -> list:
        """SOP 第一階段：TCP 全埠快速探測與非敏感埠深度版本偵測"""
        log_info.tool("nmap_scan_tcp")

        if sensitive_ports is None or not isinstance(sensitive_ports, set):
            sensitive_ports = {"80", "443", "8080", "8443"}

        TCP_ports = []

        try:
            log_info.info(f"正在對目標 {self.target_ip} 執行全 TCP 埠 (1-65535) 快速探測...")
            command = [
                "nmap", "-sT", "-p-", "--max-rate", "1000",
                "--host-timeout", "120s", self.target_ip
            ]

            result = subprocess.run(command, capture_output=True, text=True, check=False)
            matches = re.findall(r"(\d+)/tcp\s+([a-zA-Z|]+)\s+([^\n]*)", result.stdout)

            open_ports = []
            for port_str, state, info in matches:
                port_str = str(port_str)
                if state == "open":
                    open_ports.append((port_str, info))

            for port_str, info in open_ports:
                info_clean = info.strip()
                parts = info_clean.split() if info_clean else []

                if isinstance(parts, list) and parts:
                    service_name = ", ".join(parts)
                else:
                    service_name = "http" if port_str in sensitive_ports else "unknown"

                if port_str in sensitive_ports:
                    log_info.info(f"發現敏感 TCP 埠 {port_str} (狀態: open)，已略過自動版本偵測以防當機。")
                    TCP_ports.append({"port": port_str, "service": service_name, "version": "unknown"})
                    continue

                log_info.info(f"正在對非敏感 TCP 埠 {port_str} 進行深度版本偵測...")
                deep_command = [
                    "nmap", "-sT", "-p", port_str, "-sV",
                    "--version-intensity", "5", self.target_ip
                ]

                deep_result = subprocess.run(deep_command, capture_output=True, text=True, check=False)
                deep_match = re.search(rf"{port_str}/tcp\s+open\s+([^\s]+)\s*([^\n]*)", deep_result.stdout)

                if deep_match:
                    service = deep_match.group(1)
                    version_raw = deep_match.group(2).strip()
                    if not version_raw or "service unrecognized" in version_raw.lower():
                        version = "unknown"
                    else:
                        version = version_raw
                else:
                    service = service_name
                    version = "unknown"

                TCP_ports.append({"port": port_str, "service": service, "version": version})
                log_info.info(f"TCP Port {port_str} Open | Service: {service} | Version: {version}")

        except Exception as e:
            log_info.error(f"TCP Port Scan Error: {e}")

        share_memory = util.get_share_memory()
        if "ports" not in share_memory or not isinstance(share_memory["ports"], dict):
            share_memory["ports"] = {"TCP": [], "UDP": []}

        if "TCP" not in share_memory["ports"] or not isinstance(share_memory["ports"]["TCP"], list):
            share_memory["ports"]["TCP"] = []

        for tcp in TCP_ports:
            existing = next((p for p in share_memory["ports"]["TCP"] if p.get("port") == tcp["port"]), None)
            if existing:
                existing["service"] = tcp["service"]
                existing["version"] = tcp["version"]
            else:
                share_memory["ports"]["TCP"].append(tcp)

        log_info.share_memory(share_memory)
        return TCP_ports

    def nmap_scan_udp(self, sensitive_ports: set = None) -> list:
        """SOP 第一階段：UDP 埠探測 (支援快取機制)"""
        log_info.tool("nmap_scan_udp")

        cached_udp = util.get_udp_cache()
        if cached_udp:
            log_info.info("⚡ [快取命中] 檢測到 data/UDP.json 已有 UDP 掃描紀錄，自動跳過 Nmap 掃描並載入快取！")
            share_memory = util.get_share_memory()
            if "ports" not in share_memory or not isinstance(share_memory["ports"], dict):
                share_memory["ports"] = {"TCP": [], "UDP": []}

            share_memory["ports"]["UDP"] = cached_udp
            log_info.share_memory(share_memory)
            return cached_udp

        if sensitive_ports is None or not isinstance(sensitive_ports, set):
            sensitive_ports = {"53", "123", "161", "1900"}

        UDP_ports = []

        try:
            log_info.info(f"正在對目標 {self.target_ip} 執行 UDP 埠快速探測...")
            command = [
                "nmap", "-sU", "--top-ports", "100", "--max-rate", "1000",
                "--host-timeout", "120s", self.target_ip
            ]

            result = subprocess.run(command, capture_output=True, text=True, check=False)
            matches = re.findall(r"(\d+)/udp\s+([a-zA-Z|]+)\s+([^\n]*)", result.stdout)

            open_ports = []
            for port_str, state, info in matches:
                port_str = str(port_str)
                if "open" in state:
                    open_ports.append((port_str, info))

            for port_str, info in open_ports:
                info_clean = info.strip()
                parts = info_clean.split() if info_clean else []

                if isinstance(parts, list) and parts:
                    service_name = ", ".join(parts)
                else:
                    service_name = "dns" if port_str == "53" else "unknown"

                if port_str in sensitive_ports:
                    log_info.info(f"發現敏感 UDP 埠 {port_str}，已略過詳細版本探測以防當機。")
                    UDP_ports.append({"port": port_str, "service": service_name, "version": "unknown"})
                    continue

                log_info.info(f"正在對非敏感 UDP 埠 {port_str} 進行深度版本探測...")
                deep_command = [
                    "nmap", "-sU", "-p", port_str, "-sV",
                    "--version-intensity", "5", self.target_ip
                ]

                deep_result = subprocess.run(deep_command, capture_output=True, text=True, check=False)
                deep_match = re.search(rf"{port_str}/udp\s+(?:open|open\|filtered)\s+([^\s]+)\s*([^\n]*)", deep_result.stdout)

                if deep_match:
                    service = deep_match.group(1)
                    version_raw = deep_match.group(2).strip()
                    if not version_raw or "service unrecognized" in version_raw.lower():
                        version = "unknown"
                    else:
                        version = version_raw
                else:
                    service = service_name
                    version = "unknown"

                UDP_ports.append({"port": port_str, "service": service, "version": version})
                log_info.info(f"UDP Port {port_str} Open | Service: {service} | Version: {version}")

        except Exception as e:
            log_info.error(f"UDP Port Scan Error: {e}")

        util.update_udp_cache(UDP_ports)

        share_memory = util.get_share_memory()
        if "ports" not in share_memory or not isinstance(share_memory["ports"], dict):
            share_memory["ports"] = {"TCP": [], "UDP": []}

        share_memory["ports"]["UDP"] = UDP_ports
        log_info.share_memory(share_memory)

        return UDP_ports

    def analyze_web_page(self, url: str = None) -> str:
        """深度分析目標 Web 頁面 HTML，自動識別 IoT 廠商、設備類型、關鍵頁面與腳本功能"""
        log_info.tool("analyze_web_page")

        try:
            from bs4 import BeautifulSoup
        except ImportError:
            return "（錯誤：未安裝 beautifulsoup4，請執行 `pip install beautifulsoup4`）"

        if not url or not isinstance(url, str):
            url = f"http://{self.target_ip}"
        if not url.startswith("http://") and not url.startswith("https://"):
            url = f"http://{url}"

        log_info.info(f"正在抓取並分析 Web 頁面內容: {url} ...")

        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                html_content = response.read().decode("utf-8", errors="ignore")
                headers = dict(response.info())

                soup = BeautifulSoup(html_content, "html.parser")
                title = soup.title.string.strip() if (soup.title and soup.title.string) else "無標題"

                # 提煉表單欄位
                forms = []
                for form in soup.find_all("form"):
                    action = form.get("action", "")
                    method = form.get("method", "GET").upper()
                    inputs = []
                    for inp in form.find_all(["input", "button", "select", "textarea"]):
                        inp_name = inp.get("name") or inp.get("id")
                        inp_type = inp.get("type", "text")
                        if inp_name:
                            inputs.append({"name": inp_name, "type": inp_type})
                    forms.append({"action": action, "method": method, "inputs": inputs})

                # 提煉連結與指令腳本引用
                script_sources = [s.get("src") for s in soup.find_all("script") if s.get("src")]
                inline_scripts = "\n".join([s.text for s in soup.find_all("script") if s.text])
                
                links = [a["href"].strip() for a in soup.find_all("a", href=True)]
                raw_found_pages = re.findall(r'[\'"]([a-zA-Z0-9_\-\/]+\.(?:htm|html|php|cgi|asp|jsp))[\'"]', html_content)
                candidate_pages = list(set(links + raw_found_pages))[:15]

                # 調用 LLM 進行結構化 IoT 網頁剖析
                prompt_input = (
                    f"【Web 頁面分析任務】\n"
                    f"目標 URL: {url}\n"
                    f"頁面 Title: {title}\n"
                    f"Server 標頭: {headers.get('Server', 'Unknown')}\n"
                    f"發現表單: {json.dumps(forms, ensure_ascii=False)}\n"
                    f"發現網頁/腳本連結: {candidate_pages}\n"
                    f"引用的外連腳本: {script_sources}\n"
                    f"內嵌 JavaScript 摘要 (前 1000 字): {inline_scripts[:1000]}\n"
                    f"HTML 前 1500 字內容:\n{html_content[:1500]}\n\n"
                    f"請分析以上數據，識別出：\n"
                    f"1. IoT 廠商名稱 (iot_vendor) 與背景說明\n"
                    f"2. 設備種類 (device_type，如 Wireless Router, IP Camera, Gateway)\n"
                    f"3. 可深入調查的網頁頁面 (web_pages_for_deeper_investigation，如 login_real.htm, wizard_default.htm)\n"
                    f"4. 額外備註 (additional_notes，如 JS 函數 get_settings_xml, get_login_info 的用途與編碼)"
                )

                iot_analysis = {}
                try:
                    from ai.ollama import call_ollama_json
                    from tool_config import IOT_WEB_ANALYSIS_SCHEMA

                    system_web_prompt = (
                        "你是一名資深 IoT 設備 Web 安全分析專家。"
                        "請分析傳入的 HTML、標題與 JavaScript 原始碼，精確識別出設備廠商 (iot_vendor)、設備類型 (device_type)、"
                        "值得深入調查的網頁 URL (web_pages_for_deeper_investigation)，以及腳本功能與額外備註 (additional_notes)。"
                        "輸出格式必須嚴格符合 JSON Schema。"
                    )

                    iot_analysis = call_ollama_json(system_web_prompt, prompt_input, IOT_WEB_ANALYSIS_SCHEMA)
                except Exception as le:
                    log_info.warn(f"⚠️ LLM 網頁分析例外，執行啟發式備用解析: {le}")

                if not iot_analysis or not isinstance(iot_analysis, dict) or "iot_vendor" not in iot_analysis:
                    # 啟發式備用解析
                    vendor_name = "Unknown Vendor"
                    content_lower = html_content.lower() + " " + title.lower()
                    if "d-link" in content_lower:
                        vendor_name = "D-Link"
                    elif "netgear" in content_lower:
                        vendor_name = "Netgear"
                    elif "tp-link" in content_lower:
                        vendor_name = "TP-Link"
                    elif "cisco" in content_lower:
                        vendor_name = "Cisco"

                    dev_cat = "Networking Device"
                    if "router" in content_lower:
                        dev_cat = "Wireless Router"
                    elif "camera" in content_lower:
                        dev_cat = "IP Camera"

                    investigate_pages = [{"url": p, "description": "自動探測發現的潛在端點"} for p in candidate_pages[:5]]

                    iot_analysis = {
                        "iot_vendor": {
                            "name": vendor_name,
                            "description": f"{vendor_name} 網路通訊設備製造商"
                        },
                        "device_type": {
                            "category": dev_cat,
                            "description": f"由 {vendor_name} 生產的 {dev_cat} 網頁管理介面"
                        },
                        "web_pages_for_deeper_investigation": investigate_pages,
                        "additional_notes": {
                            "script_functionality": "含前端認證、重定向或 XML 設定腳本",
                            "charset": headers.get("Content-Type", "UTF-8")
                        }
                    }

                # 更新 share_memory['web_footprints']
                web_info = {
                    "target_url": url,
                    "title": title,
                    "server": headers.get("Server", "Unknown"),
                    "iot_vendor": iot_analysis.get("iot_vendor", {}),
                    "device_type": iot_analysis.get("device_type", {}),
                    "web_pages_for_deeper_investigation": iot_analysis.get("web_pages_for_deeper_investigation", []),
                    "additional_notes": iot_analysis.get("additional_notes", {}),
                    "forms": forms,
                    "discovered_endpoints": [p.get("url") if isinstance(p, dict) else str(p) for p in iot_analysis.get("web_pages_for_deeper_investigation", [])]
                }

                share_memory = util.get_share_memory()
                share_memory["web_footprints"] = web_info
                log_info.share_memory(share_memory)

                # 格式化輸出總結
                pages_summary = ""
                for p in iot_analysis.get("web_pages_for_deeper_investigation", []):
                    if isinstance(p, dict):
                        pages_summary += f"\n  - 網頁 `{p.get('url')}`: {p.get('description')}"

                vendor_obj = iot_analysis.get("iot_vendor", {})
                device_obj = iot_analysis.get("device_type", {})
                notes_obj = iot_analysis.get("additional_notes", {})

                return (
                    f"✅ [IoT Web 分析成功] ({url}):\n"
                    f"【IoT 廠商】: {vendor_obj.get('name', 'Unknown')} ({vendor_obj.get('description', '')})\n"
                    f"【設備類型】: {device_obj.get('category', 'Unknown')} ({device_obj.get('description', '')})\n"
                    f"【可深入調查的網頁】: {pages_summary if pages_summary else '無特殊頁面'}\n"
                    f"【額外備註 / JS 功能】: {notes_obj.get('script_functionality', '無')}\n"
                    f"（結構化數據已寫入 share_memory 的 web_footprints 區塊！）"
                )

        except Exception as e:
            err_msg = f"❌ 分析網頁 {url} 失敗: {e}"
            log_info.error(err_msg)
            return err_msg

    def rag_search_cve(self, query: str = "") -> str:
        """RAG 向量搜尋，直接調用 RAG_search_cve 獲得最完整 CVE 與 PoC 結構化數據"""
        log_info.tool("rag_search_cve")
        query = query.strip() if isinstance(query, str) else str(query)
        if not query:
            return "（提示：請提供搜尋關鍵字，例如 'dnsmasq 2.41'）"

        share_memory = util.get_share_memory()

        if "searched_rag_queries" not in share_memory or not isinstance(share_memory["searched_rag_queries"], list):
            share_memory["searched_rag_queries"] = []

        if query.lower() in [q.lower() for q in share_memory["searched_rag_queries"]]:
            log_info.warn(f"⚠️ [防無窮迴圈機制] 攔截重複的 RAG 查詢 `{query}`")
            existing_cves = share_memory.get("cves", [])
            return (
                f"⚡ [防重複檢索機制觸發] 系統檢測到你已經於先前對 `{query}` 執行過 RAG 漏洞檢索！\n"
                f"相關 CVE 及其完整 PoC 內容已存於 share_memory['cves'] (目前共 {len(existing_cves)} 筆)。\n"
                "🛑 【硬性要求】：請勿重複檢索，請直接發起 Web 頁面分析 (analyze_web_page) 或進行 PoC 指令驗證 (execute_cli)。"
            )

        self._init_rag_system()
        if not self._rag_systems:
            return "（錯誤：RAG 向量資料庫未升起或路徑不正確）"

        try:
            from Docker.RAG.RAG_search import search_and_analyze
            results = search_and_analyze(query, self._rag_systems)

            share_memory["searched_rag_queries"].append(query)

            if "cves" not in share_memory or not isinstance(share_memory["cves"], list):
                share_memory["cves"] = []

            existing_ids = {item.get("cve_id") or item.get("cveID") for item in share_memory["cves"] if isinstance(item, dict)}
            new_cve_count = 0
            for item in results:
                c_id = item.get("cve_id") or item.get("cveID")
                if c_id and c_id not in existing_ids:
                    share_memory["cves"].append(item)
                    existing_ids.add(c_id)
                    new_cve_count += 1

            if "task_tree" in share_memory and isinstance(share_memory["task_tree"], dict):
                try:
                    from ai.task_tree import PentestTaskTree, TaskStatus, TaskType
                    tree = PentestTaskTree.from_dict(share_memory["task_tree"])
                    parent_node_id = tree.root_ids[0] if len(tree.root_ids) > 0 else None

                    sub_node = tree.add_task(
                        title=f"RAG 漏洞檢索與 PoC 提取: {query}",
                        parent_id=parent_node_id,
                        task_type=TaskType.VULN_SCAN,
                        description=f"對 {query} 進行向量搜尋並直接提取完整 PoC 腳本"
                    )

                    tree.update_task_status(
                        node_id=sub_node.node_id,
                        status=TaskStatus.COMPLETED,
                        result=f"找到 {len(results)} 筆匹配 CVE 完整資料 (新增 {new_cve_count} 筆)"
                    )

                    share_memory["task_tree"] = tree.to_dict()
                except Exception as te:
                    log_info.error(f"❌ [Task Tree 同步失敗]: {te}")

            util.update_share_memory(share_memory)
            log_info.share_memory(share_memory)

            if not results:
                return f"（RAG 搜尋結果：資料庫中未找到與 `{query}` 相關的 CVE 漏洞。此查詢已紀錄，請勿重複搜尋。）"

            return json.dumps(results, indent=2, ensure_ascii=False)

        except Exception as e:
            err = f"❌ [RAG Search 失敗]: {e}"
            log_info.error(err)
            return err

    def nvd_search_cve(self, query: str = "") -> str:
        """線上 NVD API 查詢工具"""
        log_info.tool("nvd_search_cve")
        query = query.strip() if isinstance(query, str) else str(query)
        if not query:
            return "（提示：請提供搜尋關鍵字，例如 'dnsmasq 2.41'）"

        parts = query.split(maxsplit=1)
        product_name = parts[0] if len(parts) > 0 else query
        target_version = parts[1] if len(parts) > 1 else "unknown"

        try:
            from get_nvd import convert_to_markdown, get_vulnerability_data
        except ImportError:
            try:
                from ai.langchain.get_nvd import convert_to_markdown, get_vulnerability_data
            except ImportError:
                return "（錯誤：無法載入 get_nvd 模組）"

        try:
            log_info.info(f"🌐 透過 NVD 線上 API 查詢 -> {product_name} ({target_version})...")
            vuln_results = get_vulnerability_data(product_name, target_version)

            if vuln_results:
                share_memory = util.get_share_memory()
                if "cves" not in share_memory or not isinstance(share_memory["cves"], list):
                    share_memory["cves"] = []

                existing_ids = {item.get("cveID") or item.get("cve_id") for item in share_memory["cves"] if isinstance(item, dict)}

                for item in vuln_results:
                    cve_id = item.get("cveID") or item.get("cve_id")
                    if cve_id and cve_id not in existing_ids:
                        cvss_data = item.get("cvss", {})
                        score = cvss_data.get("score", "N/A") if isinstance(cvss_data, dict) else item.get("score", "N/A")
                        severity = cvss_data.get("severity", "UNKNOWN") if isinstance(cvss_data, dict) else item.get("severity", "UNKNOWN")

                        share_memory["cves"].append({
                            "cve_id": cve_id,
                            "service": product_name,
                            "version": target_version,
                            "score": str(score),
                            "severity": str(severity),
                            "description": item.get("description", ""),
                            "source": "NVD API"
                        })
                        existing_ids.add(cve_id)

                util.update_share_memory(share_memory)
                log_info.share_memory(share_memory)

            return convert_to_markdown(vuln_results, product_name, target_version)

        except Exception as e:
            err = f"❌ [NVD Search 失敗]: {e}"
            log_info.error(err)
            return err

    @staticmethod
    def execute_cli(command, timeout: int = 120) -> str:
        """執行 Linux CLI 滲透指令，支援缺少工具時自動安裝機制"""
        log_info.tool(command)

        if isinstance(command, list):
            command = " ".join(str(x) for x in command)
        elif not isinstance(command, str):
            command = str(command)

        clean_cmd = command.strip()
        parts = clean_cmd.split()
        main_binary = parts[0] if parts else ""

        if main_binary and main_binary in TOOL_PACKAGE_MAP:
            installed = PentestToolbox.ensure_tool_installed(main_binary)
            if not installed:
                return f"（錯誤：系統缺乏工具 `{main_binary}` 且自動安裝失敗，請執行 `sudo apt install {main_binary}`）"

        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout)
            stdout = result.stdout.strip()
            stderr = result.stderr.strip()
            output = stdout if stdout else stderr

            return output if output else "（指令執行成功，但無文字輸出）"

        except subprocess.TimeoutExpired:
            log_info.warn(f"指令 `{command}` 執行超過 {timeout} 秒超時")
            return f"（錯誤：指令 `{command}` 執行超過 {timeout} 秒超時）"
        except Exception as e:
            log_info.error(f"執行發生例外: {e}")
            return f"（執行發生例外: {e}）"

```

### 📄 `Docker/ai/langchain/util.py`

```python
# Docker/ai/langchain/util.py
import json
import os
from pathlib import Path
from typing import Any, Dict, List

def get_current_folder_path() -> Path:
    return Path(__file__).resolve().parent

def read_json(path: Path) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def write_json(path: Path, data: dict) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
        return True
    except Exception as e:
        print(f"[❌ 檔案寫入失敗] 路徑 {path} 異常: {e}")
        return False

folder = get_current_folder_path()
share_memory_file = folder / "data" / "share memory" / "share memory.json"
udp_cache_file = folder / "data" / "UDP.json"

def update_share_memory(data: dict):
    write_json(share_memory_file, data)

def get_share_memory() -> dict:
    return read_json(share_memory_file)

def init_share_memory(target_ip: str = "192.168.0.1", force_reset: bool = True) -> dict:
    """
    一開始初始化 / 重置 Share Memory 的結構化基礎狀態
    """
    initial_data = {
        "device_information": {
            "device_type": "IoT Device",
            "target_ip": target_ip,
        },
        "ports": {"TCP": [], "UDP": []},
        "web_footprints": {},
        "searched_rag_queries": [],
        "cves": [],
        "tool_history": [],
        "current_observation": "滲透測試任務啟動。",
    }
    if force_reset or not get_share_memory():
        update_share_memory(initial_data)
        return initial_data
    return get_share_memory()

def get_udp_cache() -> list:
    data = read_json(udp_cache_file)
    if isinstance(data, dict) and "UDP" in data and isinstance(data["UDP"], list):
        return data["UDP"]
    return []

def update_udp_cache(udp_list: list):
    write_json(udp_cache_file, {"UDP": udp_list})

# =====================================================================
# LangChain State & Memory Subsystem (Pentest Memory Wrapper)
# =====================================================================

class LangChainPentestMemory:
    """
    符合 LangChain 記憶體介面規範的滲透測試狀態記憶體管理器 (State Store)。
    封裝 share_memory.json，維護資產、漏洞、工具歷史與 PTT Task Tree 的全域持久化狀態。
    """

    def __init__(self, target_ip: str = "192.168.0.1", reset: bool = True):
        self.target_ip = target_ip
        self.memory_path = share_memory_file
        self.reset_memory(reset=reset)

    def reset_memory(self, reset: bool = True) -> dict:
        return init_share_memory(target_ip=self.target_ip, force_reset=reset)

    def _ensure_init(self):
        init_share_memory(target_ip=self.target_ip, force_reset=False)

    def load_memory_variables(self, inputs: Dict[str, Any] = None) -> Dict[str, Any]:
        """LangChain 標準 BaseMemory 介面：載入當前記憶體狀態變數"""
        data = get_share_memory()
        return {
            "share_memory": data,
            "ports": data.get("ports", {}),
            "web_footprints": data.get("web_footprints", {}),
            "searched_rag_queries": data.get("searched_rag_queries", []),
            "cves": data.get("cves", []),
            "tool_history": data.get("tool_history", []),
            "current_observation": data.get("current_observation", ""),
        }

    def save_context(self, inputs: Dict[str, Any], outputs: Dict[str, Any]):
        """LangChain 標準 BaseMemory 介面：寫入並更新最新互動上下文"""
        data = get_share_memory()
        if "tool_history" not in data:
            data["tool_history"] = []

        history_entry = {
            "decided_task": inputs.get("decided_task", ""),
            "tool": inputs.get("tool", {}),
            "parsed_summary": outputs.get("summary", ""),
            "extracted_facts": outputs.get("extracted_facts", {}),
            "new_evidence_found": outputs.get("new_evidence_found", False),
        }
        data["tool_history"].append(history_entry)
        data["current_observation"] = f"【上輪執行任務】: {inputs.get('decided_task', '')}\n【提煉摘要】: {outputs.get('summary', '')}"

        update_share_memory(data)

    def clear(self):
        """清空記憶體重置為初始狀態"""
        self.reset_memory(reset=True)

```

### 📄 `Docker/ai/langchain/config/logging.py`

```python
# Docker/ai/langchain/config/logging.py
import os
import json
import requests
import util

# 從環境變數讀取 FastAPI 端點，預設指向 /api/pentest/send_log
FASTAPI_LOG_URL = os.getenv("FASTAPI_LOG_URL", "http://localhost:8000/api/pentest/send_log")
ENABLE_FASTAPI_LOGGING = os.getenv("ENABLE_FASTAPI_LOGGING", "true").lower() in ("true", "1", "yes")

class log_info:
    level = 0

    @staticmethod
    def _send_to_fastapi(log_type: str, log_content: str):
        """
        將 Log 以 JSON 格式傳送給 FastAPI 端點 (/api/pentest/send_log)
        Payload 結構嚴格對應 CommandPayload (包含 log 與 log_type)
        """
        if not ENABLE_FASTAPI_LOGGING or not FASTAPI_LOG_URL:
            return

        payload = {
            "log": str(log_content),
            "log_type": str(log_type)
        }

        try:
            # 設置短 timeout (2.0s)，確保連線異常時不卡住 Agent 的滲透推演
            requests.post(FASTAPI_LOG_URL, json=payload, timeout=2.0)
        except Exception:
            # 後端未啟動或連線失敗時靜默忽略
            pass

    @staticmethod
    def info(log):
        if log_info.level >= 0:
            print(f"[INFO    ] {log}")
            log_info._send_to_fastapi("info", log)

    @staticmethod
    def tool(tool):
        if log_info.level <= 0:
            print(f"[TOOL    ] {tool}")
            log_info._send_to_fastapi("tool", tool)

    @staticmethod
    def AI_prompt(prompt):
        if log_info.level <= 0:
            print(f"[PROMPT  ] {prompt}")
            log_info._send_to_fastapi("ai_prompt", prompt)

    @staticmethod
    def AI_response(response):
        if log_info.level <= 0:
            print(f"[RESPONSE] {response}")
            log_info._send_to_fastapi("ai_response", response)

    @staticmethod
    def warn(log):
        if log_info.level <= 1:
            print(f"[WARN    ] {log}")
            log_info._send_to_fastapi("warn", log)

    @staticmethod
    def error(log):
        if log_info.level <= 2:
            print(f"[ERROR   ] {log}")
            log_info._send_to_fastapi("error", log)

    @staticmethod
    def share_memory(data):
        util.update_share_memory(data)
        log_info._send_to_fastapi("share_memory", json.dumps(data, ensure_ascii=False))

```

### 📄 `Docker/ai/langchain/ai/generation.py`

```python
# Docker/ai/langchain/ai/generation.py

import json
from ai.ollama import call_ollama_json, GENERATION_MODEL
from ai.prompt import GENERATION_SYSTEM_PROMPT
from config.logging import log_info
from tool_config import GENERATION_RESPONSE_SCHEMA

class GenerationModule:
    """
    2. 指令生成模組 (Generation Module)
    - 職責：接收 Reasoning 模組交付的高階子任務 (decided_task)，透過 Chain-of-Thought (CoT) 轉譯為具體工具呼叫或 CLI 命令。
    - 獨立 LLM Session / Prompt 上下文，隔離長序列歷程，精準生成命令。
    """

    def __init__(self):
        pass

    def run(self, decided_task: str, share_memory: dict) -> dict:
        log_info.info(f"⚡ [Generation Module] 正在將子任務轉譯為工具命令 (Model: {GENERATION_MODEL}): `{decided_task}`")

        target_ip = share_memory.get("device_information", {}).get("target_ip", "192.168.0.1")
        ports = share_memory.get("ports", {})
        web_footprints = share_memory.get("web_footprints", {})
        searched_queries = share_memory.get("searched_rag_queries", [])

        user_payload = (
            f"【高階子任務 (Decided Task)】: {decided_task}\n"
            f"【目標 IP】: {target_ip}\n"
            f"【已知開放端口 (Ports)】: {json.dumps(ports, ensure_ascii=False)}\n"
            f"【Web 腳印與 IoT 資產資訊】: {json.dumps(web_footprints, ensure_ascii=False, indent=2)}\n"
            f"【已搜尋過的 RAG 關鍵字】: {json.dumps(searched_queries, ensure_ascii=False)}\n\n"
            f"請運用 CoT 思考，將此高階子任務轉譯為最佳的工具呼叫及精確參數 (tool_name, argument)。\n"
            f"絕對不能對【已搜尋過的 RAG 關鍵字】再次產生 rag_search_cve 工具呼叫！"
        )

        response = call_ollama_json(GENERATION_SYSTEM_PROMPT, user_payload, GENERATION_RESPONSE_SCHEMA, model_name=GENERATION_MODEL)

        if not response or not isinstance(response, dict) or "tool" not in response:
            log_info.warn("⚠️ Generation 模組生成失敗，備用預設 CLI 指令")
            response = {
                "thought": "備用指令生成",
                "tool": {
                    "tool_name": "execute_cli",
                    "argument": {"cmd": f"curl -s -I http://{target_ip}"}
                }
            }

        tool_obj = response.get("tool", {})
        log_info.info(f"⚡ [Generation 指令] CoT 思考: {response.get('thought')}")
        log_info.info(f"🔧 [Generation 指令] 產出工具: {tool_obj.get('tool_name')} | 參數: {tool_obj.get('argument')}")

        return tool_obj

```

### 📄 `Docker/ai/langchain/ai/ollama.py`

```python
# Docker/ai/langchain/ai/ollama.py

import json
import os
from pathlib import Path
import re
import sys
from dotenv import load_dotenv

# LangChain Imports (支援原生 LangChain Community / LangChain Core 鏈與提示詞模版)
try:
    from langchain_community.chat_models import ChatOllama
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_core.output_parsers import JsonOutputParser
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    ChatOllama = None
    ChatPromptTemplate = None
    JsonOutputParser = None

try:
    from ollama import Client
except ImportError:
    Client = None

from config.logging import log_info

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import util

load_dotenv()

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")

# 多模型配置 Support (支援 RTX 4050 6GB 及不同模組能力最佳化)
DEFAULT_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:14b")
REASONING_MODEL = os.getenv("REASONING_MODEL", os.getenv("OLLAMA_MODEL", "qwen2.5:14b"))
GENERATION_MODEL = os.getenv("GENERATION_MODEL", os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b"))
PARSING_MODEL = os.getenv("PARSING_MODEL", os.getenv("OLLAMA_MODEL", "qwen2.5:3b"))

def get_ollama_client():
    if Client is None:
        log_info.warn("Ollama SDK 未安裝；系統將嘗試使用模擬/預設模式運作。")
        return None
    try:
        client = Client(host=OLLAMA_HOST)
        log_info.info(f"Ollama Client 初始化成功 (Host: {OLLAMA_HOST})")
        return client
    except Exception as e:
        log_info.error(f"無法初始化 Ollama 客戶端: {e}")
        return None

ollama_client = get_ollama_client()

def create_langchain_chat_model(model_name: str, temperature: float = 0.0):
    """
    建立 LangChain ChatOllama 物件
    """
    if not LANGCHAIN_AVAILABLE or ChatOllama is None:
        return None
    try:
        return ChatOllama(
            base_url=OLLAMA_HOST,
            model=model_name,
            temperature=temperature,
            format="json"
        )
    except Exception as e:
        log_info.error(f"無法建立 LangChain ChatOllama 模型 ({model_name}): {e}")
        return None

def call_ollama_json(system_prompt: str, user_content: str, response_schema: dict, model_name: str = None) -> dict:
    """
    LangChain LCEL 鏈優先呼叫與 Ollama Native Client 備用相容呼叫
    """
    target_model = model_name or DEFAULT_MODEL
    log_info.AI_prompt(f"[Model: {target_model}] System Prompt:\n{system_prompt[:250]}...\nUser Content:\n{user_content[:350]}...")

    # 1. 嘗試使用 LangChain ChatOllama + LCEL 鏈執行
    if LANGCHAIN_AVAILABLE:
        try:
            lc_llm = create_langchain_chat_model(target_model)
            if lc_llm:
                prompt_template = ChatPromptTemplate.from_messages([
                    ("system", "{system_prompt}"),
                    ("user", "{user_content}")
                ])
                chain = prompt_template | lc_llm | JsonOutputParser()
                parsed_res = chain.invoke({
                    "system_prompt": system_prompt,
                    "user_content": user_content
                })

                if isinstance(parsed_res, dict):
                    log_info.info("🔗 [LangChain Chain] 成功透過 LangChain LCEL 鏈取得並解析 JSON 回應！")
                    log_info.AI_response(json.dumps(parsed_res, ensure_ascii=False))
                    return parsed_res
        except Exception as lce:
            log_info.warn(f"⚠️ [LangChain LCEL 呼叫跳過]: {lce}，切換至 Ollama 原生客戶端處理。")

    # 2. Ollama 原生 Client 備用回退方案
    if ollama_client is None:
        log_info.error("Ollama Client 未就緒，無法呼叫 LLM。")
        return {}

    try:
        response = ollama_client.chat(
            model=target_model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            format=response_schema,
            options={"temperature": 0.0},
        )

        raw_content = response.message["content"].strip()
        log_info.AI_response(raw_content)

        cleaned_json = re.sub(r"^```(?:json)?\s*", "", raw_content, flags=re.MULTILINE)
        cleaned_json = re.sub(r"\s*```$", "", cleaned_json, flags=re.MULTILINE)

        parsed = json.loads(cleaned_json)
        if not isinstance(parsed, dict):
            log_info.error(f"LLM 回應解析非字典型態: {type(parsed)}")
            return {}

        return parsed

    except json.JSONDecodeError as e:
        log_info.error(f"LLM 回應 JSON 解析失敗: {e}，原始輸出: {raw_content[:200]}")
        return {}
    except Exception as e:
        log_info.error(f"呼叫 Ollama 模型 ({target_model}) 發生未知例外: {e}")
        return {}

```

### 📄 `Docker/ai/langchain/ai/parsing.py`

```python
# Docker/ai/langchain/ai/parsing.py

import json
from ai.ollama import call_ollama_json, PARSING_MODEL
from ai.prompt import PARSING_SYSTEM_PROMPT
from config.logging import log_info
from tool_config import PARSING_RESPONSE_SCHEMA

class ParsingModule:
    """
    3. 結果解析與壓縮模組 (Parsing Module)
    - 職責：消化 Nmap、Nikto、Web 抓包、RAG 檢索等龐大冗長 (數百至數千行) 的工具輸出 Log。
    - 提煉核心安全特徵 (Condensed Information) 與結構化數據，去除垃圾訊息。
    - 判定是否產出新證據 (new_evidence_found)，反饋給 Task Difficulty Assessment (TDA) 進行動態剪枝。
    """

    def __init__(self):
        pass

    def run(self, tool_name: str, argument: dict, raw_output: str) -> dict:
        log_info.info(f"🔍 [Parsing Module] 正在解析與壓縮工具 `{tool_name}` 的執行結果 (Model: {PARSING_MODEL}, 長度: {len(raw_output)} 字元)...")

        # 若輸出較短且明顯為系統提示，進行快速輕量處理
        if len(raw_output) < 300 and "系統提示" in raw_output:
            return {
                "summary": raw_output.strip(),
                "extracted_facts": {},
                "new_evidence_found": False,
                "status": "notice"
            }

        # 截取過長的原始 Log (最多送給 Parsing LLM 3000 字元) 供 LLM 提煉
        input_log_chunk = raw_output[:3000] if len(raw_output) > 3000 else raw_output

        user_payload = (
            f"【執行的工具】: {tool_name}\n"
            f"【工具參數】: {json.dumps(argument, ensure_ascii=False)}\n"
            f"【原始輸出 Log (Raw Output)】:\n{input_log_chunk}\n\n"
            f"請過濾雜訊，提煉 3-5 句精準的安全摘要 (summary)，提取關鍵特徵 (extracted_facts)，並標註本次是否發現新證據 (new_evidence_found)。"
        )

        response = call_ollama_json(PARSING_SYSTEM_PROMPT, user_payload, PARSING_RESPONSE_SCHEMA, model_name=PARSING_MODEL)

        if not response or not isinstance(response, dict) or "summary" not in response:
            log_info.warn("⚠️ Parsing 模組解析失敗，採用自動截斷回退方案")
            short_summary = raw_output[:300] + "..." if len(raw_output) > 300 else raw_output
            response = {
                "summary": f"工具 {tool_name} 執行完成。部分輸出：{short_summary}",
                "extracted_facts": {},
                "new_evidence_found": len(raw_output) > 200 and "錯誤" not in raw_output,
                "status": "success"
            }

        log_info.info(f"📝 [Parsing 提煉摘要]: {response.get('summary')} | 新證據: {response.get('new_evidence_found')}")
        return response

```

### 📄 `Docker/ai/langchain/ai/prompt.py`

```python
# Docker/ai/langchain/ai/prompt.py

TARGET_IP = "192.168.0.1"

INITIAL_USER_PROMPT = f"""
滲透測試任務啟動。
目標 IP: {TARGET_IP}
目前狀況：系統 SOP 已完成全 TCP/UDP 埠基礎預探測。

請讀取共享記憶體 (Share Memory) 中的開埠資訊與資產狀態，開始對開放服務進行深入列舉、漏洞檢索與驗證。
"""

# =====================================================================
# 1. 推理與決策模組 (Reasoning Module) Prompt (PentestGPT v2 EGATS & TDA)
# =====================================================================
REASONING_SYSTEM_PROMPT = f"""你是一名頂尖的自動化滲透測試隊長 (Lead Pentester / Reasoning Module)，負責驅動 PentestGPT v2 架構。
你的核心職責是管理「證據引導攻擊樹 (Evidence-Guided Attack Tree, EGATS)」，維護全域攻擊戰略，並根據任務難度評估 (TDA) 進行動態分支選擇與剪枝。

【一、角色與能力邊界】
1. 你只負責高階決策與戰略規劃 (`decided_task`)，絕不產生具體的 Linux 命令或工具參數。
2. 你的決策必須完全依據 Share Memory 中的資產情報與 EGATS 證據樹。

【二、EGATS 證據樹與 TDA 動態剪枝規範】
1. **優先推進有高價值證據支撐的分支**：例如發現的敏感 Web 端點 (`login_real.htm`, `wizard_default.htm`)、含有已知 PoC 的 CVE 項目。
2. **嚴禁選擇標記為 [Completed] 或 [Pruned] 的任務**：已被標記為 `[Pruned / 剪枝避開]` 的分支代表多次嘗試均無新證據產出，必須果斷切換至其他候選分支。
3. **嚴禁重複搜尋**：絕不能對「已執行的 RAG 關鍵字」再次生成 `rag_search_cve` 任務。

【三、階段轉銜規則】
- 若當前開放服務的資產列舉與已知 CVE 的驗證均已完成或遭 TDA 剪枝避開，請設定 `stage_completed: true` 結束本階段。

【四、輸出 JSON Schema 格式】
- thought: 高階戰略分析、EGATS 證據權重評估與 TDA 剪枝說明
- decided_task: 下一步要執行的具體高階子任務描述 (例如："分析 Port 80 Web 登入頁面 login_real.htm" 或 "發射 PoC 驗證 CVE-2020-25686")
- stage_completed: 布林值，當前階段任務是否已全部完成
"""

# =====================================================================
# 2. 指令生成模組 (Generation Module) Prompt
# =====================================================================
GENERATION_SYSTEM_PROMPT = f"""你是一名精通 Linux 滲透測試工具與漏洞利用的資深安全工程師 (Generation Module)。
你的職責是接收 Reasoning 模組傳來的「高階子任務 (decided_task)」，將其轉譯為精準、可執行的工具呼叫或 CLI 命令。

【一、可用工具庫 (Available Tools)】
1. analyze_web_page: 分析 Web 頁面 HTML 結構、表單欄位、JavaScript 與敏感 URL (參數: url)
2. rag_search_cve: 本地向量資料庫檢索完整 CVE 漏洞、詳細描述與 PoC 腳本 (參數: query, 例如 "dnsmasq 2.41")
3. nvd_search_cve: 線上 NVD API 查詢最新 CVE 與 CVSS (參數: query)
4. execute_cli: 執行具體 Linux CLI 滲透指令或驗證 PoC 腳本 (參數: cmd, 例如 "curl -i http://192.168.0.1/login_real.htm")

【二、生成原則與負面約束 (CoT & Negative Constraints)】
1. 先思考該任務需要呼叫哪個工具或哪一條 CLI 指令。
2. 絕不能對「已搜尋過的 RAG 關鍵字」再次產生 rag_search_cve 工具呼叫！
3. 確保參數精確符合目標 IP ({TARGET_IP}) 與真實服務。
4. 輸出必須嚴格符合 JSON Schema:
   - thought: Chain-of-Thought 思考過程 (為什麼選這個工具/命令)
   - tool:
     - tool_name: 工具名稱 (analyze_web_page, rag_search_cve, nvd_search_cve, execute_cli)
     - argument: 字典物件, 包含 cmd, url 或 query
"""

# =====================================================================
# 3. 結果解析與壓縮模組 (Parsing Module) Prompt (IoT 安全情資專用)
# =====================================================================
PARSING_SYSTEM_PROMPT = """你是一名專門負責日誌過濾與安全情報提煉的數據解析專家 (Parsing Module)。
滲透測試工具輸出的 Log 通常長達數百至數千行，包含大量冗餘文字。你的任務是從工具執行結果中「提煉出最關鍵的安全特徵與結論」，並判斷本次執行是否產出了「新證據 (new_evidence_found)」。

【一、解析重點與關鍵特徵】
1. 資產與設備資訊：廠商名稱 (如 D-Link)、設備類型 (如 Wireless Router)、精確軟體版本號 (如 dnsmasq 2.41)。
2. Web 特徵與端點：表單 Action 網址、Input 欄位 (如 username, password)、重定向與敏感頁面 (如 login_real.htm, wizard_default.htm)、隱藏 API。
3. 漏洞與 PoC 資訊：CVE 編號、CVSS 分數、可用的 Exploit/PoC 腳本載荷。

【二、輸出 JSON Schema 格式】
- summary: 將龐大 Log 壓縮為 3-5 句精準的安全摘要
- extracted_facts: 結構化提取的關鍵特徵物件 (如 vendor, device_type, endpoints, cves)
- new_evidence_found: 布林值，本次執行是否發現了任何先前未已知的新資產、新網頁端點或新漏洞情報
- status: "success", "failed", 或 "notice"
"""

```

### 📄 `Docker/ai/langchain/ai/reasoning.py`

```python
# Docker/ai/langchain/ai/reasoning.py

import json
from ai.ollama import call_ollama_json, REASONING_MODEL
from ai.prompt import REASONING_SYSTEM_PROMPT
from ai.task_tree import PentestTaskTree
from config.logging import log_info
from tool_config import REASONING_RESPONSE_SCHEMA
import util

class ReasoningModule:
    """
    1. 推理與決策模組 (Reasoning Module)
    - 職責：維護總體 Pentesting Task Tree (PTT) 狀態與 EGATS / TDA 高階戰略規劃。
    - 獨立 LLM Session，不存儲具體 CLI 命令或冗長工具 Log，避免 Context 污染。
    - 產出下一步的高階子任務 (decided_task)。
    """

    def __init__(self):
        pass

    def run(self, share_memory: dict, last_observation: str = "") -> dict:
        log_info.info(f"🧠 [Reasoning Module] 正在評估 EGATS 證據樹與 TDA 全域戰略 (Model: {REASONING_MODEL})...")

        # 1. 確保並渲染 PTT Task Tree 視圖與 EGATS 策略選單
        if "task_tree" in share_memory and isinstance(share_memory["task_tree"], dict):
            tree = PentestTaskTree.from_dict(share_memory["task_tree"])
            tree_text = tree.render_tree()
            egats_candidates = tree.get_egats_candidate_branches()
        else:
            target_ip = share_memory.get("device_information", {}).get("target_ip", "")
            tree = PentestTaskTree(target_ip=target_ip)
            share_memory["task_tree"] = tree.to_dict()
            util.update_share_memory(share_memory)
            tree_text = tree.render_tree()
            egats_candidates = tree.get_egats_candidate_branches()

        searched_queries = share_memory.get("searched_rag_queries", [])
        cves_list = share_memory.get("cves", [])
        web_footprints = share_memory.get("web_footprints", {})

        all_cve_ids = [
            item.get("cve_id") or item.get("cveID")
            for item in cves_list
            if isinstance(item, dict) and (item.get("cve_id") or item.get("cveID"))
        ]

        # 2. 構建 Reasoning Prompt Payload
        user_payload = (
            f"=== 滲透測試現狀與 EGATS 證據報告 ===\n"
            f"【最新觀察與執行結果 (Condensed Observation)】:\n{last_observation}\n\n"
            f"【當前任務樹狀態 (EGATS & TDA Tree)】:\n{tree_text}\n\n"
            f"【EGATS 候選分支選單】:\n"
            f"- 可推進的候選分支 (Active To-Do): {json.dumps(egats_candidates.get('active_candidates', []), ensure_ascii=False)}\n"
            f"- 已完成的分支 (Completed): {json.dumps(egats_candidates.get('completed_branches', []), ensure_ascii=False)}\n"
            f"- TDA 剪枝避開的分支 (Pruned / Failed): {json.dumps(egats_candidates.get('pruned_branches', []), ensure_ascii=False)}\n\n"
            f"【共享記憶體資產狀態 (Share Memory)】:\n"
            f"- 開放端口: {json.dumps(share_memory.get('ports', {}), ensure_ascii=False)}\n"
            f"- Web 腳印資訊 (含 IoT 廠商、設備種類與可深入調查頁面): {json.dumps(web_footprints, ensure_ascii=False, indent=2)}\n"
            f"- 已執行的 RAG 檢索關鍵字: {json.dumps(searched_queries, ensure_ascii=False)}\n"
            f"- 已檢索出的 CVE 與 PoC 列表 (共 {len(cves_list)} 筆): {json.dumps(all_cve_ids, ensure_ascii=False)}\n\n"
            f"【🚨 決策限制與注意事項】:\n"
            f"1. 嚴禁重複執行已被標記為 [Completed] 或 [Pruned] 的任務！\n"
            f"2. 嚴禁選擇已出現在「已執行的 RAG 檢索關鍵字」中的關鍵字進行二次 rag_search_cve！\n"
            f"3. 當進行 Web 頁面探測時，請優先參考 web_footprints 中的 `web_pages_for_deeper_investigation` (例如 login_real.htm, wizard_default.htm) 或對應表單介面進行針對性測試。\n"
            f"4. 若已知 CVE 中包含 PoC，可直接下達驗證該 PoC 漏洞的子任務；若所有開放服務與 CVE 均已分析與驗證完成，請設定 stage_completed: true。\n\n"
            f"請評估當前進度，更新 PTT 戰略，並輸出下一步決定的高階子任務 (decided_task)。"
        )

        response = call_ollama_json(REASONING_SYSTEM_PROMPT, user_payload, REASONING_RESPONSE_SCHEMA, model_name=REASONING_MODEL)

        if not response or not isinstance(response, dict):
            log_info.warn("⚠️ Reasoning 回應無效，採用預設預備任務")
            response = {
                "thought": "無法取得無效回應，備用策略：列舉與分析開放服務",
                "decided_task": "分析開放服務並檢索潛在漏洞",
                "stage_completed": False
            }

        log_info.info(f"🧠 [Reasoning 決策] 戰略思考: {response.get('thought')}")
        log_info.info(f"🎯 [Reasoning 決策] 選定子任務: {response.get('decided_task')}")

        return response

```

### 📄 `Docker/ai/langchain/ai/task_tree.py`

```python
# Docker/ai/langchain/ai/task_tree.py
from enum import Enum
import json
from typing import Any, Dict, List, Optional
import uuid

class TaskStatus(str, Enum):
    TO_DO = "to_do"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    PRUNED = "pruned"  # TDA / EGATS: 自動動態剪枝 (Task Difficulty Index 超限)

class TaskType(str, Enum):
    RECON = "recon"
    VULN_SCAN = "vuln_scan"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    REPORT = "report"

def _clean_str_id(val: Any) -> Optional[str]:
    """清洗並收斂變數，確保 ID 必為單一字串，徹底防止 list 類型導致 dict unhashable 錯誤"""
    if val is None:
        return None
    if isinstance(val, list):
        return _clean_str_id(val[0]) if len(val) > 0 else None
    return str(val)

class TaskNode:

    def __init__(
        self,
        node_id: str,
        title: str,
        parent_id: Optional[str] = None,
        task_type: TaskType = TaskType.RECON,
        status: TaskStatus = TaskStatus.TO_DO,
        description: str = "",
        result: str = "",
        attempts_count: int = 0,
        tdi_score: float = 0.0,
        evidence_ids: Optional[List[str]] = None,
    ):
        self.node_id = _clean_str_id(node_id) or str(uuid.uuid4())[:8]
        self.title = str(title)
        self.parent_id = _clean_str_id(parent_id)
        self.task_type = (
            task_type if isinstance(task_type, TaskType) else TaskType(task_type)
        )
        self.status = (
            status if isinstance(status, TaskStatus) else TaskStatus(status)
        )
        self.description = str(description) if description else ""
        self.result = str(result) if result else ""
        self.children_ids: List[str] = []
        
        # PentestGPT v2 TDA & EGATS 欄位
        self.attempts_count = int(attempts_count)
        self.tdi_score = float(tdi_score)  # Task Difficulty Index (0.0 ~ 1.0)
        self.evidence_ids = evidence_ids if isinstance(evidence_ids, list) else []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "title": self.title,
            "parent_id": self.parent_id,
            "task_type": self.task_type.value,
            "status": self.status.value,
            "description": self.description,
            "result": self.result,
            "children_ids": self.children_ids,
            "attempts_count": self.attempts_count,
            "tdi_score": self.tdi_score,
            "evidence_ids": self.evidence_ids,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TaskNode":
        node = cls(
            node_id=data.get("node_id", str(uuid.uuid4())[:8]),
            title=data.get("title", ""),
            parent_id=data.get("parent_id"),
            task_type=TaskType(data.get("task_type", "recon")),
            status=TaskStatus(data.get("status", "to_do")),
            description=data.get("description", ""),
            result=data.get("result", ""),
            attempts_count=data.get("attempts_count", 0),
            tdi_score=data.get("tdi_score", 0.0),
            evidence_ids=data.get("evidence_ids", []),
        )
        raw_children = data.get("children_ids", [])
        if isinstance(raw_children, list):
            node.children_ids = [_clean_str_id(c) for c in raw_children if _clean_str_id(c)]
        return node

class PentestTaskTree:

    def __init__(self, target_ip: str = ""):
        self.target_ip = target_ip
        self.nodes: Dict[str, TaskNode] = {}
        self.root_ids: List[str] = []
        self._init_default_tree()

    def _init_default_tree(self):
        target_str = f" ({self.target_ip})" if self.target_ip else ""

        node_recon = self.add_task(
            title=f"1. 資產偵察與服務列舉{target_str}",
            task_type=TaskType.RECON,
            description="探測 TCP/UDP 開放埠與 Web 介面結構",
        )

        node_vuln = self.add_task(
            title="2. 漏洞檢索與評估",
            task_type=TaskType.VULN_SCAN,
            description="對已知服務進行 RAG / NVD CVE 與 PoC 查驗",
        )

        node_exploit = self.add_task(
            title="3. 漏洞利用與驗證",
            task_type=TaskType.EXPLOIT,
            description="執行針對性 Payload 或 CLI 命令驗證安全風險",
        )

    def add_task(
        self,
        title: str,
        parent_id: Optional[Any] = None,
        task_type: TaskType = TaskType.RECON,
        description: str = "",
        node_id: Optional[Any] = None,
    ) -> TaskNode:
        clean_node_id = _clean_str_id(node_id) or str(uuid.uuid4())[:8]
        clean_parent_id = _clean_str_id(parent_id)

        node = TaskNode(
            node_id=clean_node_id,
            title=title,
            parent_id=clean_parent_id,
            task_type=task_type,
            status=TaskStatus.TO_DO,
            description=description,
        )

        self.nodes[clean_node_id] = node

        if clean_parent_id and clean_parent_id in self.nodes:
            if clean_node_id not in self.nodes[clean_parent_id].children_ids:
                self.nodes[clean_parent_id].children_ids.append(clean_node_id)
        else:
            if clean_node_id not in self.root_ids:
                self.root_ids.append(clean_node_id)

        return node

    def record_attempt(self, node_id: Any, success: bool = True, new_evidence_found: bool = False) -> TaskStatus:
        """
        PentestGPT v2 TDA (Task Difficulty Assessment) 核心機制:
        記錄節點執行嘗試次數與新證據產出。若連續嘗試 >= 3 次且未有新證據產出，自動判定該攻擊路徑無效並進行剪枝 (Pruning)。
        """
        clean_id = _clean_str_id(node_id)
        if not clean_id or clean_id not in self.nodes:
            return TaskStatus.TO_DO

        node = self.nodes[clean_id]
        node.attempts_count += 1

        if new_evidence_found:
            node.tdi_score = max(0.0, node.tdi_score - 0.3)
            if success:
                node.status = TaskStatus.COMPLETED
        else:
            node.tdi_score = min(1.0, node.tdi_score + 0.35)
            # 若連續嘗試 3 次以上且沒有產出新證據 -> TDA 自動剪枝
            if node.attempts_count >= 3:
                node.status = TaskStatus.PRUNED
                node.result = f"TDA 動態剪枝: 連續 {node.attempts_count} 次嘗試無新證據 (TDI={node.tdi_score:.2f})"
            elif not success:
                node.status = TaskStatus.FAILED

        return node.status

    def update_task_status(
        self,
        node_id: Any,
        status: TaskStatus,
        result: str = "",
        description: Optional[str] = None,
    ) -> bool:
        clean_id = _clean_str_id(node_id)
        if not clean_id or clean_id not in self.nodes:
            return False

        node = self.nodes[clean_id]
        node.status = (
            status if isinstance(status, TaskStatus) else TaskStatus(status)
        )
        if result:
            node.result = str(result)
        if description is not None:
            node.description = str(description)

        return True

    def render_tree(self) -> str:
        """將 Task Tree 轉為純文字樹狀圖 (含 TDA 剪枝與嘗試統計)"""
        lines = ["=== 【Pentesting Task Tree - EGATS & TDA 樹狀圖】 ==="]

        def _render_node(node_id_val: Any, prefix: str = "", is_last: bool = True):
            clean_id = _clean_str_id(node_id_val)
            if not clean_id:
                return
            node = self.nodes.get(clean_id)
            if not node:
                return

            status_text = {
                TaskStatus.TO_DO: "[To-Do]",
                TaskStatus.IN_PROGRESS: "[In-Progress]",
                TaskStatus.COMPLETED: "[Completed]",
                TaskStatus.FAILED: "[Failed]",
                TaskStatus.PRUNED: "[Pruned / 剪枝避開]",
            }.get(node.status, "[Unknown]")

            branch = "└── " if is_last else "├── "
            attempts_info = f" (嘗試: {node.attempts_count}次, TDI: {node.tdi_score:.1f})" if node.attempts_count > 0 else ""
            line = (
                f"{prefix}{branch}{status_text} (ID: {node.node_id}) {node.title}{attempts_info}"
            )

            if node.result:
                short_res = (
                    node.result[:50] + "..."
                    if len(node.result) > 50
                    else node.result
                )
                line += f" -> 結果: {short_res}"

            lines.append(line)

            child_prefix = prefix + ("    " if is_last else "│   ")
            child_count = len(node.children_ids)
            for idx, child_id in enumerate(node.children_ids):
                _render_node(child_id, child_prefix, idx == child_count - 1)

        root_count = len(self.root_ids)
        for idx, root_id in enumerate(self.root_ids):
            _render_node(root_id, "", idx == root_count - 1)

        return "\n".join(lines)

    def get_egats_candidate_branches(self) -> Dict[str, List[str]]:
        """回傳 EGATS 候選分支視圖，明確標註可執行候選與已剪枝/已完成分支"""
        active_candidates = []
        completed_branches = []
        pruned_branches = []

        for nid, node in self.nodes.items():
            if node.status == TaskStatus.TO_DO:
                active_candidates.append(f"[{node.node_id}] {node.title}")
            elif node.status == TaskStatus.COMPLETED:
                completed_branches.append(f"[{node.node_id}] {node.title}")
            elif node.status in [TaskStatus.PRUNED, TaskStatus.FAILED]:
                pruned_branches.append(f"[{node.node_id}] {node.title} (原因: {node.result})")

        return {
            "active_candidates": active_candidates,
            "completed_branches": completed_branches,
            "pruned_branches": pruned_branches,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_ip": self.target_ip,
            "nodes": {nid: node.to_dict() for nid, node in self.nodes.items()},
            "root_ids": [_clean_str_id(r) for r in self.root_ids if _clean_str_id(r)],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PentestTaskTree":
        tree = cls.__new__(cls)
        tree.target_ip = data.get("target_ip", "")
        tree.nodes = {}
        for nid, ndata in data.get("nodes", {}).items():
            clean_nid = _clean_str_id(nid)
            if clean_nid and isinstance(ndata, dict):
                tree.nodes[clean_nid] = TaskNode.from_dict(ndata)
        raw_roots = data.get("root_ids", [])
        if isinstance(raw_roots, list):
            tree.root_ids = [_clean_str_id(r) for r in raw_roots if _clean_str_id(r)]
        else:
            tree.root_ids = []
        return tree

```


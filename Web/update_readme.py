import os

# 設定要抓取的目標資料夾
TARGET_DIRS = ["."]
# 💡 1. 新增要排除的資料夾名稱名稱集合 (Set)
EXCLUDE_DIRS = {"__pycache__", ".git", "venv", ".idea", ".vscode", "temp", "exploitdb"}

TARGET_EXTENSIONS = (".js", ".html", ".css", ".py")
OUTPUT_FILE = "README.md"

def get_language_tag(filename):
    """根據副檔名判定 Markdown 程式碼區塊的語法標註"""
    if filename.endswith(".py"):
        return "python"
    elif filename.endswith(".sh"):
        return "bash"
    elif filename.endswith(".txt"):
        return "text"
    return ""

def generate_readme():
    with open(OUTPUT_FILE, "w", encoding="utf-8") as outfile:
        outfile.write("更新後的專案程式碼\n")
        outfile.write("# AI Agent 模組程式碼與架構說明\n\n")
        outfile.write(
            "本檔案由 `update_readme.py` 自動生成，僅彙整 `AI Agent` 目錄內之核心程式碼。\n\n"
        )

        for target_dir in TARGET_DIRS:
            if not os.path.exists(target_dir):
                print(f"[!] 找不到目錄: {target_dir}，請確認目錄名稱。")
                continue

            outfile.write(f"## 📁 資料夾: `{target_dir}/` \n\n")

            # 💡 2. 記得加上 dirs 接收資料夾清單
            for root, dirs, files in os.walk(target_dir):
                
                # 💡 3. 原地修改 dirs，跳過包含在 EXCLUDE_DIRS 中的子資料夾
                dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

                for file in sorted(files):
                    if file.endswith(TARGET_EXTENSIONS) and not file.startswith("."):
                        file_path = os.path.join(root, file)
                        lang = get_language_tag(file)

                        if "update_readme.py" in file_path:
                            continue

                        outfile.write(f"### 📄 `{file_path}`\n\n")
                        outfile.write(f"```{lang}\n")
                        try:
                            with open(file_path, "r", encoding="utf-8") as infile:
                                outfile.write(infile.read())
                        except Exception as e:
                            outfile.write(f"# 無法讀取檔案內容: {e}\n")
                        outfile.write("\n```\n\n")

    print(f"[OK] 已成功將 AI Agent 程式碼打包寫入 {OUTPUT_FILE}！")

if __name__ == "__main__":
    generate_readme()

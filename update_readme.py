import os

# 設定僅抓取 "AI Agent" 資料夾
TARGET_DIRS = ["AI Agent"]
TARGET_EXTENSIONS = (".py", ".sh", ".txt")
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
        outfile.write("# AI Agent 模組程式碼與架構說明\n\n")
        outfile.write(
            "本檔案由 `update_readme.py` 自動生成，僅彙整 `AI Agent` 目錄內之核心程式碼。\n\n"
        )

        for target_dir in TARGET_DIRS:
            if not os.path.exists(target_dir):
                print(f"[!] 找不到目錄: {target_dir}，請確認目錄名稱。")
                continue

            outfile.write(f"## 📁 資料夾: `{target_dir}/` \n\n")

            for root, _, files in os.walk(target_dir):
                for file in sorted(files):
                    if file.endswith(TARGET_EXTENSIONS) and not file.startswith(
                        "."
                    ):
                        file_path = os.path.join(root, file)
                        lang = get_language_tag(file)

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
from pathlib import Path
import os

def modifyConfig():
    """修改 FAP 與 Firmadyne 的配置路徑"""
    home = os.path.expanduser("~")
    # 修正路徑解析，確保正確對應到掛載進來的 Tool
    current_dir = os.path.join(home, Path(__file__).resolve().parent)

    fap_config = os.path.join(current_dir, "Firmware_tool/firmware-analysis-plus/fap.config")
    firmadyne_config = os.path.join(current_dir, "Firmware_tool/firmware-analysis-plus/firmadyne/firmadyne.config")
    firmadyne_dir = os.path.join(current_dir, "Firmware_tool/firmware-analysis-plus/firmadyne")

    # 檢查設定檔是否存在再修改
    for cfg in [fap_config, firmadyne_config]:
        if not os.path.exists(cfg):
            print(f"[!] 找不到設定檔: {cfg}")
            return

    # 修改 fap.config
    with open(fap_config, 'r') as f:
        lines = f.readlines()
    if len(lines) > 2:
        lines[2] = f"firmadyne_path={firmadyne_dir}\n"
        with open(fap_config, 'w') as f:
            f.writelines(lines)

    # 修改 firmadyne.config
    with open(firmadyne_config, 'r') as f:
        lines = f.readlines()
    if len(lines) > 3:
        lines[3] = f"FIRMWARE_DIR={firmadyne_dir}\n"
        with open(firmadyne_config, 'w') as f:
            f.writelines(lines)
    
    print("[OK] FAP 與 Firmadyne 配置路徑已更新。")

if __name__ == "__main__":
    modifyConfig()
# python-tools/utils/adb_helper.py
import subprocess
import shutil

def check_adb_installed() -> bool:
    """Kiểm tra xem lệnh adb có tồn tại trong hệ thống không."""
    return shutil.which("adb") is not None

def get_connected_devices() -> list:
    """Lấy danh sách các thiết bị/emulator đang kết nối."""
    try:
        result = subprocess.run(["adb", "devices"], capture_output=True, text=True, check=True)
        lines = result.stdout.strip().split('\n')[1:]
        devices = [line.split('\t')[0] for line in lines if line.strip() and '\tdevice' in line]
        return devices
    except Exception:
        return []
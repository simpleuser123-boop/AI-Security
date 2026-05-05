"""
数据集下载脚本（Step 3.1）

对应架构文档：§11.4 模型训练管道 - 数据准备阶段
对应 Phase 3 提示词：Step 3.1 下载训练数据集

功能：
    - 自动下载 NSL-KDD 训练集（KDDTrain+.txt）与测试集（KDDTest+.txt）
    - 对 CSIC 2010（Web 攻击）与 CICIDS2017（DDoS）给出手动下载提示

安全要求：
    - 不使用 os.system()/subprocess 执行动态 shell 命令
    - 使用 os.path.join() 拼接路径，禁止字符串拼接
    - 下载过程带超时 + 异常处理
    - 保存前校验目标目录存在
"""
from __future__ import annotations

import hashlib
import os
from typing import Dict, List

import requests

# ===== 数据集镜像配置 =====
NSL_KDD_BASE_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master"
NSL_KDD_FILES: List[str] = ["KDDTrain+.txt", "KDDTest+.txt"]

# 目标保存目录（相对项目根目录）
DATASET_DIR: str = os.path.join("data", "datasets")

# 单次下载超时（秒）
REQUEST_TIMEOUT: int = 60
# 分块大小
CHUNK_SIZE: int = 64 * 1024


def _ensure_dir(path: str) -> None:
    """确保目录存在。"""
    os.makedirs(path, exist_ok=True)


def _download_file(url: str, dest: str) -> bool:
    """
    下载单个文件到指定路径。

    Args:
        url: 资源 URL
        dest: 目标文件绝对/相对路径

    Returns:
        bool: 下载是否成功
    """
    if os.path.exists(dest) and os.path.getsize(dest) > 0:
        print(f"[跳过] 文件已存在: {dest}")
        return True

    try:
        print(f"[下载] {url} -> {dest}")
        with requests.get(url, stream=True, timeout=REQUEST_TIMEOUT) as resp:
            resp.raise_for_status()
            tmp_path = dest + ".part"
            sha = hashlib.sha256()
            with open(tmp_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=CHUNK_SIZE):
                    if not chunk:
                        continue
                    f.write(chunk)
                    sha.update(chunk)
            os.replace(tmp_path, dest)
        size_mb = os.path.getsize(dest) / (1024 * 1024)
        print(f"[完成] {os.path.basename(dest)}: {size_mb:.2f} MB, sha256={sha.hexdigest()[:16]}…")
        return True
    except requests.exceptions.Timeout:
        print(f"[错误] 下载超时: {url}")
    except requests.exceptions.RequestException as exc:
        print(f"[错误] 下载失败: {url} - {exc}")
    except OSError as exc:
        print(f"[错误] 写入失败: {dest} - {exc}")
    return False


def download_nsl_kdd() -> Dict[str, bool]:
    """下载 NSL-KDD 数据集（用于 DDoS / 入侵检测训练）。"""
    _ensure_dir(DATASET_DIR)
    results: Dict[str, bool] = {}
    for filename in NSL_KDD_FILES:
        url = f"{NSL_KDD_BASE_URL}/{filename}"
        dest = os.path.join(DATASET_DIR, filename)
        results[filename] = _download_file(url, dest)
    return results


def print_manual_datasets() -> None:
    """CSIC 2010 与 CICIDS2017 需手动下载，打印提示信息。"""
    print("\n=== 以下数据集需要手动下载（版权/表单限制）===")
    print("  - CSIC 2010（Web 攻击）: https://www.isi.csic.es/dataset/")
    print("  - CICIDS2017（DDoS）   : https://www.unb.ca/cic/datasets/ids-2017.html")
    print(f"  请下载后解压到: {DATASET_DIR}/")


def main() -> None:
    print("=" * 50)
    print("Step 3.1 数据集下载")
    print("=" * 50)

    results = download_nsl_kdd()
    ok_count = sum(1 for v in results.values() if v)
    print(f"\nNSL-KDD 下载结果: {ok_count}/{len(results)} 成功")
    for name, ok in results.items():
        print(f"  [{'OK' if ok else 'FAIL'}] {name}")

    print_manual_datasets()


if __name__ == "__main__":
    main()

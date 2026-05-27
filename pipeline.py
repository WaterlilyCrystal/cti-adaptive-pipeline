"""
CTI Adaptive Pipeline - Main Orchestrator
"""
import argparse
import yaml
from datetime import datetime


def load_config(path="config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def phase_collect(cfg: dict):
    """Phase 1: Thu thập dữ liệu từ tất cả nguồn."""
    print(f"[{datetime.utcnow().isoformat()}] === PHASE 1: COLLECTION ===")
    # TODO (Sinh viên A): import và gọi collectors.py + social.py
    # from core.collectors import fetch_rss_all, fetch_cve_all
    # from core.social import fetch_reddit, fetch_telegram
    raise NotImplementedError("Sinh viên A implement phase_collect()")


def phase_process(cfg: dict):
    """Phase 2: Làm sạch, dedup, dịch, chấm điểm."""
    print(f"[{datetime.utcnow().isoformat()}] === PHASE 2: PROCESSING ===")
    # TODO (Sinh viên A): import và gọi processor.py
    # from core.processor import run_processing
    raise NotImplementedError("Sinh viên A implement phase_process()")


def phase_analyze(cfg: dict):
    """Phase 3: IOC extraction, ATT&CK mapping, Sigma, Report."""
    print(f"[{datetime.utcnow().isoformat()}] === PHASE 3: ANALYSIS ===")
    # TODO (Sinh viên B): import và gọi intelligence.py + defense.py
    # from core.intelligence import run_intelligence
    # from core.defense import run_defense
    raise NotImplementedError("Sinh viên B implement phase_analyze()")


def run_full(cfg: dict):
    phase_collect(cfg)
    phase_process(cfg)
    phase_analyze(cfg)
    print(f"[{datetime.utcnow().isoformat()}] === PIPELINE DONE ===")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CTI Adaptive Pipeline")
    parser.add_argument(
        "--phase",
        choices=["collect", "process", "analyze", "all"],
        default="all",
        help="Chạy từng phase hoặc toàn bộ"
    )
    args = parser.parse_args()
    cfg = load_config()

    phase_map = {
        "collect": phase_collect,
        "process": phase_process,
        "analyze": phase_analyze,
        "all": run_full,
    }
    phase_map[args.phase](cfg)
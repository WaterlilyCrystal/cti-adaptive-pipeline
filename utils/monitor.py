import psutil
import time
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_system_stats() -> dict:
    """Fetches real-time RAM, CPU, and optional GPU utilization metrics."""
    ram = psutil.virtual_memory()
    cpu = psutil.cpu_percent(interval=0.5)
    
    stats = {
        "ram_used_gb": round(ram.used / 1e9, 2),
        "ram_total_gb": round(ram.total / 1e9, 2),
        "ram_percent": ram.percent,
        "cpu_percent": cpu,
        "gpu_vram_used": 0.0,
        "gpu_vram_total": 0.0
    }
    
    try:
        import GPUtil
        gpus = GPUtil.getGPUs()
        if gpus:
            stats["gpu_vram_used"] = round(gpus[0].memoryUsed, 2)
            stats["gpu_vram_total"] = round(gpus[0].memoryTotal, 2)
    except ImportError:
        # GPUtil not installed or no NVIDIA GPU available
        pass
    except Exception as e:
        logging.debug(f"Failed to read GPU statistics: {str(e)}")
        
    return stats


def get_available_ram_gb() -> float:
    ram = psutil.virtual_memory()
    return round(ram.available / (1024 ** 3), 2)


def get_effective_available_ram_gb(cfg: dict | None = None) -> float:
    cfg = cfg or {}
    resources = cfg.get("resources", {})
    override = resources.get("available_ram_gb_override", 0)
    reserve = resources.get("reserve_ram_gb", 2)
    try:
        override_value = float(override)
    except (TypeError, ValueError):
        override_value = 0.0
    try:
        reserve_value = max(0.0, float(reserve))
    except (TypeError, ValueError):
        reserve_value = 2.0

    if override_value > 0:
        return round(override_value, 2)
    return round(max(0.5, get_available_ram_gb() - reserve_value), 2)


def apply_runtime_profile(cfg: dict | None = None) -> dict:
    cfg = cfg or {}
    resources = cfg.setdefault("resources", {})
    if resources.get("auto_tune", True) is False:
        return cfg

    llm = cfg.setdefault("llm", {})
    pipeline = cfg.setdefault("pipeline", {})
    available_ram_gb = get_effective_available_ram_gb(cfg)

    if available_ram_gb < 4:
        profile_name = "low"
        limits = {
            "llm_num_ctx": 2048,
            "llm_probe_num_ctx": 256,
            "phase3_max_items": 1,
            "batch_processing_size": 100,
            "dedup_window_size": 25,
            "enable_semantic_dedup": False,
        }
    elif available_ram_gb < 8:
        profile_name = "medium"
        limits = {
            "llm_num_ctx": 4096,
            "llm_probe_num_ctx": 384,
            "phase3_max_items": 2,
            "batch_processing_size": 250,
            "dedup_window_size": 50,
            "enable_semantic_dedup": False,
        }
    else:
        profile_name = "high"
        limits = {
            "llm_num_ctx": 8192,
            "llm_probe_num_ctx": 512,
            "phase3_max_items": 5,
            "batch_processing_size": 500,
            "dedup_window_size": 100,
            "enable_semantic_dedup": pipeline.get("enable_semantic_dedup", True),
        }

    llm["num_ctx"] = min(int(llm.get("num_ctx", 8192)), limits["llm_num_ctx"])
    llm["probe_num_ctx"] = min(int(llm.get("probe_num_ctx", 512)), limits["llm_probe_num_ctx"])
    pipeline["phase3_max_items"] = min(int(pipeline.get("phase3_max_items", 5)), limits["phase3_max_items"])
    pipeline["batch_processing_size"] = min(int(pipeline.get("batch_processing_size", 500)), limits["batch_processing_size"])
    pipeline["dedup_window_size"] = min(int(pipeline.get("dedup_window_size", 100)), limits["dedup_window_size"])
    if limits["enable_semantic_dedup"] is False:
        pipeline["enable_semantic_dedup"] = False

    resources["_effective_available_ram_gb"] = available_ram_gb
    resources["_applied_profile"] = profile_name
    logging.info(
        "Runtime profile=%s effective_ram_gb=%.2f llm_num_ctx=%s phase3_max_items=%s batch_processing_size=%s",
        profile_name,
        available_ram_gb,
        llm["num_ctx"],
        pipeline["phase3_max_items"],
        pipeline["batch_processing_size"],
    )
    return cfg

def check_before_llm_call(threshold_percent: float = 85.0):
    """
    Blocks processing execution sequentially if RAM usage exceeds the safe threshold.
    Prevents Local LLM execution from causing Operating System thrashing.
    """
    stats = get_system_stats()
    while stats["ram_percent"] > threshold_percent:
        logging.warning(f"System RAM resource exhaustion detected ({stats['ram_percent']}%). Throttling execution for 30 seconds...")
        time.sleep(30)
        stats = get_system_stats()
    return stats

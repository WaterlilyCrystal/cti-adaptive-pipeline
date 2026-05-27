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
import logging
import subprocess
import time
from datetime import datetime, timedelta

from utils import db_handler

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

JOBS = {
    "social_ingestion": {"tier": "social", "interval_hours": 2},
    "news_ingestion": {"tier": "news", "interval_hours": 6},
    "vulnerability_sync": {"tier": "vuln", "interval_hours": 24},
    "phase2_processing": {"phase": "process", "interval_hours": 2},
    "phase3_analysis": {"phase": "analyze", "interval_hours": 2},
}


def run_pipeline_command(args: list[str]) -> bool:
    try:
        subprocess.run(["python", "pipeline.py", *args], check=True)
        return True
    except subprocess.CalledProcessError as exc:
        logging.error("Pipeline command failed: %s", exc)
        return False


def daemon_loop():
    logging.info("Adaptive CTI stratified scheduler started.")
    next_runs = {
        job_name: datetime.now()
        for job_name in JOBS
    }

    while True:
        now = datetime.now()
        for job_name, job in JOBS.items():
            if now < next_runs[job_name]:
                continue

            logging.info("[%s] Running job: %s", now.isoformat(), job_name)
            if "tier" in job:
                run_pipeline_command(["--phase", "collect", "--tier", job["tier"]])
            else:
                run_pipeline_command(["--phase", job["phase"]])

            next_time = now + timedelta(hours=job["interval_hours"])
            next_runs[job_name] = next_time
            conn = db_handler.init_db()
            db_handler.touch_scheduler_job(conn, job_name, next_time.isoformat())
            conn.close()

        time.sleep(60)


if __name__ == "__main__":
    daemon_loop()

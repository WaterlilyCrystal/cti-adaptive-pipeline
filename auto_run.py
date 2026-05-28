import time
import subprocess
import logging
from datetime import datetime

# Configure the waiting time between pipeline runs (in minutes)
# For demo/defense purposes, set to 5. For production, set to 60 or 120.
WAIT_TIME_MINUTES = 60 

# Configure logging format
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def run_pipeline():
    """
    Executes the main pipeline orchestrator as a subprocess.
    """
    logging.info("="*60)
    logging.info(f"[{datetime.now().strftime('%H:%M:%S')}] ACTIVATING NEW PIPELINE CYCLE...")
    logging.info("="*60)
    
    try:
        # Executes the equivalent of typing `python pipeline.py --phase all` in the terminal
        subprocess.run(["python", "pipeline.py", "--phase", "all"], check=True)
        logging.info("[+] Pipeline cycle completed successfully.")
        
    except subprocess.CalledProcessError as e:
        logging.error(f"[-] An error occurred during Pipeline execution: {e}")
    except FileNotFoundError:
        logging.error("[-] pipeline.py not found. Please ensure you are running this from the root project directory.")

if __name__ == "__main__":
    logging.info("🚀 Adaptive CTI Auto-Scheduler Daemon Started.")
    logging.info(f"⏳ Execution frequency set to: {WAIT_TIME_MINUTES} minutes per run.")
    
    while True:
        # 1. Trigger the pipeline
        run_pipeline()
        
        # 2. Calculate sleep time and enter idle state
        next_run_seconds = WAIT_TIME_MINUTES * 60
        logging.info(f"💤 System entering idle state. Waking up in {WAIT_TIME_MINUTES} minutes...")
        
        time.sleep(next_run_seconds)
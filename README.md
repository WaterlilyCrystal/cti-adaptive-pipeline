# CTI Adaptive Pipeline

Hệ thống tự động thu thập, phân tích Cyber Threat Intelligence và sinh báo cáo + Sigma rules có thể deploy ngay.

## Dành cho tổ chức chưa có đội TI riêng

## Tech Stack
- **LLM**: Ollama + Qwen 2.5 3B (local, không cần cloud)
- **ATT&CK**: mitreattack-python (official MITRE library)
- **IOC**: iocextract
- **Storage**: SQLite + ChromaDB
- **UI**: Streamlit

## Cài đặt

```bash
# 1. Cài Ollama và pull model
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull qwen2.5:3b-instruct-q4_K_M

# 2. Cài Python dependencies
pip install -r requirements.txt
python -m spacy download en_core_web_sm

# 3. Download ATT&CK STIX data (một lần)
curl -L https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json \
     -o enterprise-attack.json

# 4. Setup config
cp .env.example .env   # Điền API keys
# Chỉnh org profile trong config.yaml

# 5. Chạy pipeline
python pipeline.py --phase=collect
python pipeline.py --phase=process
python pipeline.py --phase=analyze
# Hoặc chạy toàn bộ:
python pipeline.py --phase=all

# 6. Mở dashboard
streamlit run app.py
```

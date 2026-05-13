@echo off
cd /d E:\soc-homelab\argus
set ES_PASS=YOUR_ES_PASS_HERE
set ES_USER=elastic
set CLAUDE_API_KEY=YOUR_CLAUDE_API_KEY_HERE
start "behavior_detector" cmd /k "cd /d E:\soc-homelab\argus && set ES_PASS=YOUR_ES_PASS_HERE && set ES_USER=elastic && python behavior_detector.py"
timeout /t 3 >nul
start "case_builder" cmd /k "cd /d E:\soc-homelab\argus && set ES_PASS=YOUR_ES_PASS_HERE && set ES_USER=elastic && python case_builder.py"
timeout /t 3 >nul
start "argus_api" cmd /k "cd /d E:\soc-homelab\argus && set ES_PASS=YOUR_ES_PASS_HERE && set ES_USER=elastic && set CLAUDE_API_KEY=YOUR_CLAUDE_API_KEY_HERE && python -m uvicorn app:app --host 0.0.0.0 --port 8000"

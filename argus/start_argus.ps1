$env:ES_USER = "elastic"
$env:ES_PASS = "YOUR_ES_PASS_HERE"
$env:CLAUDE_API_KEY = "YOUR_CLAUDE_API_KEY_HERE"

Write-Host "[1/4] Starting behavior_detector..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList '-NoExit', '-Command', '$env:ES_USER="elastic"; $env:ES_PASS="YOUR_ES_PASS_HERE"; Set-Location E:\soc-homelab\argus; python behavior_detector.py'

Start-Sleep -Seconds 3

Write-Host "[2/4] Starting case_builder..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList '-NoExit', '-Command', '$env:ES_USER="elastic"; $env:ES_PASS="YOUR_ES_PASS_HERE"; Set-Location E:\soc-homelab\argus; python case_builder.py'

Start-Sleep -Seconds 3

Write-Host "[3/4] Starting argus_api..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList '-NoExit', '-Command', '$env:ES_USER="elastic"; $env:ES_PASS="YOUR_ES_PASS_HERE"; $env:CLAUDE_API_KEY="YOUR_CLAUDE_API_KEY_HERE"; Set-Location E:\soc-homelab\argus; python -m uvicorn app:app --host 0.0.0.0 --port 8000'

Start-Sleep -Seconds 3

Write-Host "[4/4] Starting Vite frontend..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList '-NoExit', '-Command', 'Set-Location E:\soc-homelab\argus\frontend-react; npm run dev'

Write-Host "All processes started. Open http://localhost:5173" -ForegroundColor Green

# Quick Start - NGFW Project
$p = Split-Path -Parent $MyInvocation.MyCommand.Path
Start-Process powershell -ArgumentList "-NoExit","-Command","cd '$p\backend'; `$env:DB_HOST='127.0.0.1'; `$env:DB_PORT='5432'; `$env:DB_NAME='ngfw_db'; `$env:DB_USER='postgres'; `$env:DB_PASS='1234'; python app.py"
Start-Sleep -Seconds 2
Start-Process powershell -ArgumentList "-NoExit","-Command","cd '$p\frontend-react'; npm start"
Write-Host "`n✅ Started! Frontend: http://localhost:3000 | Backend: http://localhost:5000/api`n" -ForegroundColor Green

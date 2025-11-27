@echo off
start "Backend" /D "%~dp0backend" cmd /k "set DB_HOST=127.0.0.1&&set DB_PORT=5432&&set DB_NAME=ngfw_db&&set DB_USER=postgres&&set DB_PASS=1234&&python app.py"
timeout /t 2 /nobreak >nul
start "Frontend" /D "%~dp0frontend-react" cmd /k "npm start"
echo ✅ Started! Frontend: http://localhost:3000 | Backend: http://localhost:5000/api

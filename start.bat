@echo off
echo 🚀 Starting InfraScanner Pro...

REM Check if Docker is running
docker info >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker is not running. Please start Docker and try again.
    pause
    exit /b 1
)

REM Navigate to docker directory
cd infrastructure\docker

REM Check if .env file exists
if not exist ..\..\.env (
    echo ⚠️  No .env file found. Creating default configuration...
    (
        echo # MongoDB Configuration
        echo MONGO_INITDB_ROOT_USERNAME=admin
        echo MONGO_INITDB_ROOT_PASSWORD=admin123
        echo.
        echo # Application Configuration
        echo CONSOLE_USERNAME=admin
        echo CONSOLE_PASSWORD=admin123
        echo.
        echo # Slack Integration ^(Optional^)
        echo SLACK_BOT_TOKEN=
        echo SLACK_CHANNEL=#security-alerts
        echo.
        echo # Google Chat Webhook ^(Optional^)
        echo WEBHOOK_URL=
    ) > ..\..\.env
    echo ✅ Created default .env file. Please edit it with your configuration.
)

REM Start the application
echo 🔧 Starting containers...
docker-compose up -d

REM Wait for containers to be ready
echo ⏳ Waiting for services to start...
timeout /t 10 /nobreak >nul

REM Check if containers are running
docker-compose ps | findstr "Up" >nul
if errorlevel 1 (
    echo ❌ Failed to start containers. Check logs with: docker-compose logs
    pause
    exit /b 1
) else (
    echo ✅ InfraScanner Pro is running!
    echo.
    echo 🌐 Access the application at: http://localhost:8180
    echo 👤 Username: admin
    echo 🔑 Password: admin123
    echo.
    echo 📊 MongoDB: localhost:27017
    echo 📝 Logs: docker-compose logs -f
    echo.
    echo 🛑 To stop: docker-compose down
    echo.
    pause
)

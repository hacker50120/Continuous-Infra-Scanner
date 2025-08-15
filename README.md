# InfraScanner Pro 🛡️

A modern, automated infrastructure vulnerability scanner with comprehensive security monitoring and real-time alerting capabilities.

## 🚀 Features

- **Automated Scanning**: Scheduled vulnerability assessments using Nuclei
- **Real-time Monitoring**: Continuous infrastructure change detection
- **Modern UI**: Dark theme with futuristic design inspired by ProjectDiscovery
- **Slack Integration**: Real-time alerts and reports
- **Asset Management**: Technology stack detection and asset inventory
- **Risk Scoring**: Comprehensive risk assessment and scoring
- **Multi-target Support**: Scan multiple IPs and networks concurrently

## 📁 Project Structure

```
infrascanner-pro/
├── app/                        Main application
│   ├── src/                   Python source code
│   │   ├── app.py            Flask web application
│   │   ├── script.py         Main scanning logic
│   │   ├── scheduler.py      Automated scheduling
│   │   ├── vulnerability_scanner.py  Nuclei integration
│   │   ├── slack_notifier.py Slack notifications
│   │   └── mongo_connection.py Database connection
│   ├── templates/            HTML templates
│   ├── static/               CSS, JS, images
│   ├── logs/                 Application logs
│   ├── requirements.txt      Python dependencies
│   ├── pm2.config.js         Process management
│   └── ip.txt                Target-IP configuration
├── infrastructure/
│   ├── docker/               Docker configuration
│   │   ├── Dockerfile        Application container
│   │   └── docker-compose.yaml Multi-container setup
│   ├── terraform/            Terraform IaC
│   └── kubernetes/           K8s manifests
├── docs/                      Additional documentation
├── scripts/                   Helper scripts (start.sh, start.bat)
├── tests/                     Test files
└── README.md                  Main project doc
```

## 🛠️ Quick Start

### Prerequisites
- Docker and Docker Compose
- Python 3.11+ (for local development)
- Go 1.19+ (for Nuclei)

### 1. Clone and Setup
```bash
git clone <repository-url>
cd infrascanner-pro
```

### 2. Configure Environment
Create a `.env` file in the root directory:
```bash
# MongoDB Configuration
MONGO_INITDB_ROOT_USERNAME=admin
MONGO_INITDB_ROOT_PASSWORD=admin123

# Application Configuration
CONSOLE_USERNAME=admin
CONSOLE_PASSWORD=admin123

# Slack Integration (Optional)
SLACK_BOT_TOKEN=xoxb-your-slack-bot-token
SLACK_CHANNEL=#security-alerts

# Google Chat Webhook (Optional)
WEBHOOK_URL=https://chat.googleapis.com/v1/spaces/...
```

### 3. Configure Target IPs
Edit `app/ip.txt` and add your target IP addresses:
```
192.168.1.1
10.0.0.1
172.16.0.1
```

### 4. Start the Application
```bash
cd infrastructure/docker
docker-compose up -d
```

### 5. Access the Application
- **Web Interface**: http://localhost:8180
- **Username**: admin
- **Password**: admin123

## 🔧 Configuration

### Scan Schedule
The application runs automated scans at:
- **Daily**: 2:00 AM
- **Weekly**: Sunday 1:00 AM (Comprehensive scan)

### Vulnerability Scanning
- **Nuclei Integration**: Comprehensive vulnerability assessment
- **Severity Levels**: Critical, High, Medium, Low
- **Template Categories**: CVEs, Misconfigurations, Exposures

### Alerting
- **Slack Notifications**: Real-time vulnerability and change alerts
- **Infrastructure Changes**: Port changes, service modifications
- **Risk Scoring**: Automated risk assessment (0-100 scale)

## 📊 Dashboard Features

### Security Operations Center
- **Real-time Metrics**: Total scans, alerts, vulnerabilities, assets
- **Risk Assessment**: Visual risk scoring with trend analysis
- **Vulnerability Breakdown**: Severity-based categorization
- **Recent Activity**: Latest scans and alerts
- **Quick Actions**: Direct access to all features

### Scan Results
- **Port Analysis**: Open ports and services
- **HTTP Details**: Web service information
- **Technology Stack**: Detected frameworks and servers
- **Vulnerability Reports**: Detailed Nuclei scan results

## 🔒 Security Features

### Authentication
- HTTP Basic Authentication
- Configurable credentials
- Session management

### Data Protection
- Encrypted MongoDB storage
- Secure environment variables
- Audit logging

### Network Security
- Rate limiting on scans
- Timeout protection
- Error handling and recovery

## 🚀 Advanced Features

### Asset Management
- **Technology Detection**: Web servers, frameworks, CMS
- **Service Discovery**: HTTP, HTTPS, custom ports
- **Inventory Tracking**: Asset history and changes

### Reporting
- **Daily Reports**: Automated Slack summaries
- **Export Capabilities**: JSON, CSV formats
- **Trend Analysis**: Historical data visualization

### Integration
- **Slack**: Real-time notifications and reports
- **Google Chat**: Webhook-based alerts
- **API Ready**: RESTful endpoints for external tools

## 🛠️ Development

### Local Development
```bash
cd app
pip install -r requirements.txt
python app.py
```

### Adding New Features
1. **Vulnerability Scanners**: Extend `vulnerability_scanner.py`
2. **Notification Channels**: Add to `slack_notifier.py`
3. **UI Components**: Modify templates in `app/templates/`
4. **Styling**: Update CSS in `app/static/css/`

### Testing
```bash
cd tests
python -m pytest
```

## 📈 Monitoring and Logs

### Application Logs
- **Location**: `app/logs/`
- **Scan Results**: `logs/scan_logs/`
- **Vulnerability Reports**: `logs/nuclei_results/`
- **Scheduler Logs**: `logs/scheduler.log`

### Container Logs
```bash
docker-compose logs -f infrascanner-app
docker-compose logs -f infrascanner-mongodb
```

## 🔧 Troubleshooting

### Common Issues
1. **Port Conflicts**: Change ports in `docker-compose.yaml`
2. **MongoDB Connection**: Check environment variables
3. **Slack Notifications**: Verify bot token and permissions
4. **Scan Failures**: Check target IP accessibility

### Performance Tuning
- **Concurrent Scans**: Adjust `max_workers` in `script.py`
- **Scan Timeouts**: Modify timeout values in `vulnerability_scanner.py`
- **Rate Limiting**: Configure Nuclei rate limits

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: Create a GitHub issue
- **Documentation**: Check the `docs/` directory
- **Community**: Join our discussions

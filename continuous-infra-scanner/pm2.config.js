module.exports = {
  apps: [
    {
      name: 'flask-app',
      script: 'app.py',
      interpreter: 'python3',
      watch: false,  // Disable watching for production
      ignore_watch: ['logs', 'ip.txt', 'scan_logs'],  // Ignore changes in these paths
      env: {
        FLASK_ENV: 'production'
      }
    }
  ]
};

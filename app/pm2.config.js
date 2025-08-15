module.exports = {
  apps: [
    {
      name: 'flask-app',
      script: 'src/app.py',
      interpreter: 'python3',
      watch: false,  // Disable watching for production
      ignore_watch: ['logs', 'ip.txt', 'scan_logs'],  // Ignore changes in these paths
      env: {
        FLASK_ENV: 'production'
      }
    },
    {
      name: 'scanner-scheduler',
      script: 'src/scheduler.py',
      interpreter: 'python3',
      watch: false,
      ignore_watch: ['logs', 'ip.txt', 'scan_logs'],
      env: {
        NODE_ENV: 'production'
      }
    }
  ]
};

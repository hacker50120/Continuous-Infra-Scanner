# Continuous-Infra-Scanner

The **Continuous-Infra-Scanner** system enhances infrastructure security by leveraging **NMAP** to conduct thorough security assessments, offering both graphical visualizations and tabular reports that detail open ports, IP addresses, and potential vulnerabilities. These visual insights and structured data empower security teams to quickly identify and prioritize critical areas of concern.

In addition to **NMAP** scanning, the system integrates seamlessly with **Nessus Professional**, further strengthening vulnerability management by adding in-depth analysis and actionable insights into security posture. This dual integration ensures a comprehensive approach to threat detection, enabling organizations to efficiently address vulnerabilities across their infrastructure.

A key feature of Continuous-Infra-Scanner is its **comprehensive logging** capability. The system meticulously records all events and alerts, providing a valuable resource for **incident response** and **historical analysis**. This enables security teams to review past issues, track patterns over time, and maintain a robust audit trail, which is essential for effective monitoring and continuous improvement in security practices.

---

# Demonstration Video
For a step-by-step walkthrough of the setup, configuration, and usage of this project, please refer to the demonstration video. [https://youtu.be/DqtDd37b6xw](https://www.youtube.com/watch?v=DqtDd37b6xw)

---

## Features

- Automated infrastructure scanning using Nessus
- Data storage in MongoDB for scan results
- Basic authentication for secure access to the console
- Configurable webhook notifications

---

## Getting Started

Follow these instructions to set up, configure, and run the `Continuous-Infra-Scanner` project using Docker Compose.

### Prerequisites

1. [Docker](https://www.docker.com/get-started) installed on your machine
2. [Docker Compose](https://docs.docker.com/compose/install/) installed
3. A [Nessus](https://www.tenable.com/products/nessus) account and report scan ID for your infrastructure scans
4. Webhook URL for notifications (Google Chat, Slack, Telegram, etc.)

---

## Installation and Setup

### Step 1: Clone the Repository

Clone this repository to your local machine:

```bash
git clone https://github.com/hacker50120/Continuous-Infra-Scanner.git
cd Continuous-Infra-Scanner
```

# Step 2: Create a .env File
```
In the root directory of the project, create a .env file to configure environment variables for the application.
Here’s a template for the .env file:

# Basic Authentication Credentials for Console Access
CONSOLE_USERNAME=admin
CONSOLE_PASSWORD=StrongPassword@123  # Change to a secure password of your choice

# MongoDB Credentials
MONGO_INITDB_ROOT_USERNAME=MongoDBUser
MONGO_INITDB_ROOT_PASSWORD=MongoDBPassword
MONGO_URI=mongodb://MongoDBUser:MongoDBPassword@mongodb:27017/mydatabase?authSource=admin

# Nessus Credentials
NESSUS_HOSTNAME=nessus.com
NESSUS_USERNAME=nessus_username
NESSUS_PASSWORD=nessus_password
REPORT_NUMBER_ID=<Nessus Report ID>  # Replace with your actual Nessus report ID

# Webhook URL for Notifications
WEBHOOK_URL=https://chat.googleapis.com/v1/spaces/<token>

```

# Explanation of Variables:
1. `CONSOLE_USERNAME` and `CONSOLE_PASSWORD`: Basic authentication credentials for accessing the scanner console. Set a strong password.
2. `MONGO_INITDB_ROOT_USERNAME`, `MONGO_INITDB_ROOT_PASSWORD`, and `MONGO_URI`: MongoDB credentials and connection URI for storing scan results.
3. `NESSUS_HOSTNAME`, `NESSUS_USERNAME`, and `NESSUS_PASSWORD`: Nessus credentials to authenticate with your Nessus account.
4. `REPORT_NUMBER_ID`: The unique ID of the Nessus scan report. You can find it in the report URL: `https://nessus.com/#/scans/reports/<ID>/hosts`.
5. `WEBHOOK_URL`: URL for the notification webhook. The default example is for Google Chat, but you can customize it for other platforms.

---

# Step 3: Start the Project with Docker Compose
Run Docker Compose to build and start the project in detached mode:
```
docker-compose up -d
```
This command builds the `Continuous-Infra-Scanner` image and starts both MongoDB and the scanner app.

---

# Step 4: Access the Console
After launching, you can access the scanner console in your web browser:

- URL: `http://localhost:8180`
- Username: `admin` (or the value of `CONSOLE_USERNAME` in your .env file)
- Password: The value of `CONSOLE_PASSWORD` in your `.env` file

---

# Changing the Webhook Notification Service
By default, the project is set up to send notifications through Google Chat. To use a different platform like Slack or Telegram, update the `WEBHOOK_URL` in your `.env` file and modify the webhook formatting in the code to match the target platform’s API.

Example Webhook URLs
- Google Chat: `https://chat.googleapis.com/v1/spaces/<token>`
- Slack: `https://hooks.slack.com/services/<token>`
- Telegram: Set up a bot using the Telegram Bot API and get the webhook URL.

---

# Nessus Report ID
To configure **REPORT_NUMBER_ID**:

Log into Nessus and navigate to your scan reports.
Locate the report ID in the URL of the scan report, such as `https://nessus.com/#/scans/reports/123344/hosts`, where `123344` is the report ID.
Set `REPORT_NUMBER_ID` to this ID in your `.env` file.


---

# Troubleshooting

**Common Issues**

1. **Authentication Errors:** Verify that your `NESSUS_USERNAME`, `NESSUS_PASSWORD`, `CONSOLE_USERNAME`, and `CONSOLE_PASSWORD` are correctly set in the `.env` file.
2. **MongoDB Connection:** Ensure the `MONGO_URI` matches the credentials provided for `MONGO_INITDB_ROOT_USERNAME` and `MONGO_INITDB_ROOT_PASSWORD`.
2. **Webhook Notifications Not Sent:** Check the format of the `WEBHOOK_URL` and ensure it matches the format required by your notification platform (e.g., Google Chat, Slack).

**Resetting the Project**
To reset the containers and volumes, run:

```
docker-compose down -v
docker-compose up -d
```

---

# Contributing

Feel free to fork this repository, make improvements, and submit pull requests. Contributions are welcome!

---

# License
This project is licensed under the MIT License. See the `LICENSE` file for details.
```
This Markdown file includes all the necessary setup, configuration, and troubleshooting information and is formatted to be easily readable in GitHub’s Markdown viewer. You can replace `<link to demonstration video>` with the actual video link when it’s available.
```

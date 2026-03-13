# Guardian-Desk

🛡️ Guardian Desk – Cybersecurity Toolkit

A lightweight Cybersecurity Monitoring Toolkit that helps detect system vulnerabilities, monitor file integrity, analyze logs, and evaluate password strength in real time.

This project provides a centralized security dashboard that aggregates multiple security checks and generates a risk score based on system activity.

📌 Project Overview

Guardian Desk is a Flask-based cybersecurity toolkit designed to help users monitor their system security through multiple modules such as:

System Security Audit

Network Monitoring

File Integrity Monitoring (FIM)

Security Log Monitoring

Password Strength Analysis

Real-time Risk Scoring Dashboard

The toolkit collects system data, analyzes it, and presents insights through a web dashboard interface.

The backend processes the security checks while the frontend provides a visual dashboard for monitoring system health.

🚀 Key Features
🔍 1. System Security Audit

Analyzes system configuration and running services.

Includes:

OS information

CPU, memory, and disk usage

Running processes

Open ports detection

Boot time analysis

This module collects system metrics using psutil and platform APIs.

🌐 2. Network Monitoring

Scans the system network and provides insights such as:

Network interfaces

Active TCP/UDP connections

Remote IP addresses

Network traffic statistics

The module uses psutil to analyze network connections and detect remote devices connected to the system.

📂 3. File Integrity Monitoring (FIM)

Detects unauthorized file changes using SHA-256 hashing.

Capabilities:

Baseline file hashing

Detect file modification

Detect deleted files

Monitor critical system files

The system stores a baseline hash and compares it with current file hashes to detect tampering.

📜 4. Security Log Monitoring

Analyzes system authentication logs to detect suspicious activity such as:

Failed login attempts

Successful logins

SSH access

Sudo usage

Suspicious IP addresses

The module parses system logs like /var/log/auth.log and /var/log/syslog.

🔑 5. Password Strength Analyzer

Evaluates password security based on multiple factors:

Length

Character diversity

Entropy calculation

Dictionary password detection

Pattern detection

The analyzer calculates a strength score (0-100) and estimates the password cracking time.

📊 6. Risk Score Dashboard

The dashboard aggregates data from all modules and calculates a security risk score.

Risk score factors include:

Risky open ports

Failed login attempts

Modified files

Firewall status

The system generates alerts when suspicious activity is detected.

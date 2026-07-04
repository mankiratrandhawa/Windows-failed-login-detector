# Windows Failed Login Detector

A Python script to parse Windows Security event logs and extract failed login attempts (Event ID 4625). Exports results to a CSV file for further analysis.

## Features

- Parses plain text exports from Windows Event Viewer
- Extracts timestamp, username, and source IP address
- Handles multiple log entries and various text formats
- Outputs clean CSV with headers
- No external dependencies (uses only standard Python libraries)

## Requirements

- Python 3.6 or higher

## Installation

No installation required. Just clone the repository:

```bash
git clone https://github.com/your-username/windows-failed-login-detector.git
cd windows-failed-login-detector

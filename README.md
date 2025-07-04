# Auditdog: Real-time Security Auditing and Monitoring Platform

Auditdog is a full-stack, containerized security auditing platform that provides real-time monitoring of system events, including SSH logins, command executions, and privilege escalations. It leverages LLMs for risk analysis, provides a modern web interface for log visualization, and sends real-time alerts for high-risk activities.

## Features mapped with Conversations

- **Conversation 1: Real-time SSH Login Detection**
  - Implemented real-time SSH login detection from system logs.
  - Added event deduplication and persistent storage.
  - Included comprehensive debug logging.
  - **Key Fixes & Optimizations:**
    - Replaced deprecated `pyinotify` with the modern `watchdog` library.
    - Fixed regex patterns for proper SSH log parsing.
    - Added graceful shutdown handling (SIGTERM/SIGINT).
    - Configured as a systemd service for background operation.
  - **Architecture:**
    - Modular design with file watching, parsing, and storage components.
    - Event-driven real-time log processing.

- **Conversation 2: FastAPI Backend & PostgreSQL Integration**
  - Implemented a FastAPI backend for SSH event monitoring.
  - Added PostgreSQL integration with SQLAlchemy 2.0.
  - Created Pydantic models and CRUD operations.
  - Built REST endpoints for SSH event management.
  - Added Docker containerization with health checks.

- **Conversation 3: Command Execution Monitoring & Risk Analysis**
  - Extended AuditDog agent to monitor command execution via `auditd` logs.
  - Integrated OpenAI LLM for risk categorization (critical, high, medium, low).
  - Added a backend API endpoint for LLM risk analysis requests.
  - Implemented Telegram bot notifications for high-risk commands.
  - Made the risk threshold configurable for dynamic alert triggering.

- **Conversation 4: LLM-Powered Command Explanation**
  - Added a command explanation feature with the `auditdog` prefix.
  - Integrated an LLM via the OpenAI API for command analysis.
  - Implemented a retry mechanism (up to 5 attempts).
  - Added a JSON caching system with size limits.
  - Implemented cache expiration (7-day auto-clear).
  - Added loading animations and user feedback.

- **Conversation 5: Privilege Escalation & Failed Auth Detection**
  - Added privilege escalation detection for SSH sessions.
  - Implemented tracking of failed authentication attempts.
  - Added configurable failure count limits with time windows.
  - Integrated session termination and user lockout mechanisms.
  - Fixed duplicate event logging and optimized regex patterns.

- **Conversation 6: Brute-Force Protection**
  - Added SSH brute-force protection with an IP/user lockout system.
  - Integrated failed login detection from `auth` logs.
  - Extended the Telegram notification system for lockout alerts.
  - Fixed duplicate log entries and regex pattern issues.

- **Conversation 7: Backend API & Structured Logging**
  - Optimized log storage to send logs to the backend API alongside local storage.
  - Added structured API endpoints for SSH events, command executions, privilege escalations, and brute-force attempts.
  - Implemented Pydantic validation schemas for all log entry types.
  - Created an API client in the agent for seamless backend communication.
  - Fixed database connection issues and request timeout problems.

- **Conversation 8: React Frontend for Log Visualization**
  - Implemented a React frontend for AuditDog log visualization.
  - Added PostgreSQL API integration for fetching security logs.
  - Created a responsive dashboard with a collapsible sidebar.
  - Integrated charts for visual log analysis across all event types.
  - Fixed API parameter handling and navigation functionality.

## Unit Test Screenshots

- [Fast API Unit Test](https://drive.google.com/file/d/1c5W3KR1H1JFL0zYdKMT23hzFEb9977tq/view)
- [LLM Categorization Unit Test](https://drive.google.com/file/d/1jmvVuNOKRctq3vjCJBJdwHuBpNjjgv-n/view)
- [Command Explanation Unit Test](https://drive.google.com/file/d/1EgV2P2U3tO4-Xx-mxd5RZHKnRBn5ANwd/view)
- [Frontend Unit Test](https://drive.google.com/file/d/1joBf_KH2BjqSmZQZaok8TjcggqRIDBtN/view)

## Project Structure

```
.
├── auditagent/             # The agent that runs on monitored systems
│   ├── api/                # Client for communicating with the backend API
│   ├── core/               # Core logic for event handling
│   ├── main.py             # Main entry point for the agent
│   ├── parsers/            # Log parsing modules (e.g., for auth.log, auditd)
│   ├── storage/            # Local log storage
│   └── watchers/           # File/log watching components
│
├── backend/                # The FastAPI backend server
│   ├── app/                # Main application source code
│   ├── auditdog.sh         # Installation and management script
│   ├── docker-compose.yml  # Docker Compose for development
│   ├── Dockerfile          # Dockerfile for the backend service
│   └── pyproject.toml      # Project dependencies and metadata
│
├── frontend/               # The React frontend for visualization
│   ├── public/             # Public assets
│   ├── src/                # React source code (components, services, etc.)
│   └── package.json        # Frontend dependencies
│
├── .gitignore              # Git ignore file
└── README.md               # This file
```

## Prerequisites

- **Docker & Docker Compose:** For running the containerized services (backend, database).
- **Python & Pip:** For running the `auditagent` locally.
- **Git:** For cloning the repository.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/HarshTuring/auditdog
    cd auditdog
    ```

2.  **Set up the Backend:**
    - Navigate to the `backend` directory:
      ```bash
      cd backend
      ```
    - Create a `.env` file from the example and update it with your environment variables (e.g., database credentials, API keys):
      ```bash
      cp .env.example .env
      ```
    - Build and start the services using Docker Compose:
      ```bash
      docker-compose up --build -d
      ```

3.  **Set up the Frontend:**
    - Navigate to the `frontend` directory:
      ```bash
      cd ../frontend
      ```
    - Install the dependencies:
      ```bash
      npm install
      ```
    - Start the development server:
      ```bash
      npm start
      ```

4.  **Set up the Audit Agent:**
    - Navigate to the `auditagent` directory:
      ```bash
      cd ../auditagent
      ```
    - Install the required Python packages:
      ```bash
      pip install -r requirements.txt
      ```
    - Run the agent:
      ```bash
      python main.py
      ```

## Running the Application

- **Backend API:** [http://localhost:8000](http://localhost:8000)
- **Frontend UI:** [http://localhost:3000](http://localhost:3000)

## Testing

-   **Backend tests:**
    ```bash
    cd backend
    pytest
    ```
-   **Frontend tests:**
    ```bash
    cd frontend
    npm test
    ```

## Technologies Used

- **Backend:**
  - Python
  - FastAPI
  - SQLAlchemy 2.0
  - PostgreSQL
  - Watchdog
  - OpenAI API
  - Telegram API
- **Frontend:**
  - React
  - Chart.js
- **System & Tooling:**
  - Docker & Docker Compose
  - `auditd`
  - `systemd`

## Project Outcome

Auditdog provides real-time security monitoring, using an LLM to detect and analyze system threats. It offers a central dashboard for visualization and configurable alerts for proactive threat response.
# Message Board Application

A full-stack Python messaging ecosystem built with Flask and RESTful APIs. This project features a central server and two distinct clients for human interaction and automated system monitoring.

## System Overview

The ecosystem consists of three main components:
1. **The Server (`board-server`)**: A Flask-based REST API that handles user authentication (JWT), message storage (SQLAlchemy), and tag management.
2. **The Human Client (`board-client`)**: An interactive terminal interface for users to manually read, send, and filter messages.
3. **The Automated Monitor (`board-monitor`)**: A background daemon that watches a specific inbox for system-level commands (e.g., triggering a system shutdown).

## Prerequisites

* **Python:** `>= 3.14`
* **Package Manager:** `uv`
* **System Utilities (for the Monitor):** `at` and `systemctl` (Linux)

## Installation & Setup

1. **Clone the repository and install dependencies:**
   Using `uv`, you can easily sync the project and install the defined entry-point scripts:
   ```bash
   uv sync

   
## ---------------------------------------------------------------------------------------------------------------------------------------------------

```markdown
# Message Board Application

A full-stack Python messaging ecosystem built with Flask and RESTful APIs. This project features a central server and two distinct clients for human interaction and automated system monitoring.

## System Overview

The ecosystem consists of three main components:
1. **The Server (`board-server`)**: A Flask-based REST API that handles user authentication (JWT), message storage (SQLAlchemy), and tag management.
2. **The Human Client (`board-client`)**: An interactive terminal interface for users to manually read, send, and filter messages.
3. **The Automated Monitor (`board-monitor`)**: A background daemon that watches a specific inbox for system-level commands (e.g., triggering a system shutdown).

## Prerequisites

* **Python:** `>= 3.14`
* **Package Manager:** `uv`
* **System Utilities (for the Monitor):** `at` and `systemctl` (Linux)

## Installation & Setup

1. **Clone the repository and install dependencies:**
   Using `uv`, you can easily sync the project and install the defined entry-point scripts:
   ```bash
   uv sync

```

2. **Initialize the Database:**
Before running the clients, you must initialize the SQLite database and create your user accounts.
```bash
uv run python src/server/manage_db.py

```



---

## Usage

Because the application is integrated with `uv` scripts, you can run the components directly from the root of the project using `uv run`.

### 1. Message Board Server

The server must be running before any client can connect. It hosts the API and manages the database.

**To run the server:**

```bash
uv run board-server

```

*By default, the server binds to `0.0.0.0:5000` and is accessible on your local network.*

### 2. Human Interface Client

This is the interactive terminal application you use to navigate the message board manually.

**Configuration:**
If you are hosting the server somewhere other than `localhost`, set the base URL using an environment variable before running:

```bash
export BOARD_BASE_URL="http://your-server-ip:5000"

```

**To run the client:**

```bash
uv run board-client

```

Upon launch, you will be prompted to enter your credentials. The interactive menu allows you to send private/public messages, subscribe to tags, and manage your inbox.

### 3. Automated Monitor

The monitor runs continuously in the background, polling the server every minute. It checks the authenticated user's private messages. If it receives a message from the user **"daniel"** containing exactly the word **"shutdown"**, it will attempt to schedule a system poweroff.

**Configuration:**
For security purposes, credentials must be passed via environment variables so they do not appear in system process lists.

```bash
export BOARD_USERNAME="your_monitor_username"
export BOARD_PASSWORD="your_monitor_password"
export BOARD_BASE_URL="[http://127.0.0.1:5000](http://127.0.0.1:5000)" # Optional

```

**To run the monitor:**

```bash
uv run board-monitor

```

**Important Notes for the Monitor:**

* **Logging:** Output is not printed to the console; it is appended to `monitor.log` in the directory where the script is executed.
* **System Privileges:** The host machine must have the `at` command installed (`sudo apt install at`). Furthermore, the user executing the monitor must have `sudo` privileges configured to run `/usr/bin/systemctl poweroff` without a password prompt.

```

```

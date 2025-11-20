# client_app/him.py
# Automated Interface of MessageBoardClient
# Ensure the server is running before executing this.
# You'll need to create users using 'manage_db.py' first.
from client import MessageBoardClient
import os

import logging
import subprocess
import sys
import shutil

logger = logging.getLogger()

def schedule_shutdown() -> str:
    """
    Schedules a system shutdown using 'at' and 'systemctl'.
    The shutdown is scheduled for 1 minute from the current time.
    """
    result = ""
    # 1. specific command required by the user
    command_to_run = "systemctl poweroff"

    # 2. Verify 'at' is installed on the system
    if not shutil.which("at"):
        logger.error("Error: The 'at' command is not found. Please install it (e.g., sudo apt install at).")
        return

    try:
        # 3. Execute the command
        # Equivalent to: echo "systemctl poweroff" | at now + 1 minute
        process = subprocess.run(
            ["at", "now", "+", "1", "minute"],
            input=command_to_run.encode('utf-8'), # Pass command to stdin
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True # Raises CalledProcessError if return code is non-zero
        )

        # 4. Success feedback
        # 'at' usually prints job information to stderr, even on success.
        logger.info(f"success: {process.stderr.decode('utf-8').strip()}")
    except subprocess.CalledProcessError as e:
        # Handle errors (e.g., user is not root, or syntax error)
        logger.error(f"Failed to schedule shutdown. Error:\n{e.stderr.decode('utf-8')}")
    except PermissionError:
        logger.error("Failed to schedule shutdown. You need root privileges to schedule this command.")

    return result

def check_private_messages(username: str, password: str) -> None:
    client = MessageBoardClient(base_url="https://danielwaltherberns.pythonanywhere.com/") # Adjust if server runs elsewhere

    logger.info("Message Board Automated Interface start")

    success = False
    if not client.token:
        try:
            if username and password:
                success, _ = client.login(username, password)
            else:
                logger.error("Invalid username and password")
            if success:
                private_messages = client.get_private_messages()
                for a_message in private_messages:
                    sender = a_message.get('sender_username', '!')
                    content = a_message.get('content', '!' )
                    if sender == 'daniel':
                        if content == 'shutdown':
                            schedule_shutdown()
        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}")
    else:
        logger.error("An unexpected error occurred: not null client token")

    logger.info("Message Board Automated Interface done")



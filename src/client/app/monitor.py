# Automated Interface of MessageBoardClient
# Ensure the server is running before executing this.
# You'll need to create users using 'manage_db.py' first.
import os
import time
import logging
import subprocess
import shutil
from client import MessageBoardClient

# Configure logging to write to a file
logging.basicConfig(
    level=logging.INFO,  # Adjusted logging level to INFO
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='monitor.log', # Log output to this text file
    filemode='a' # Append mode
)
logger = logging.getLogger()

def schedule_shutdown() -> str:
    """
    Schedules a system shutdown using 'at' and 'systemctl'.
    The shutdown is scheduled for 1 minute from the current time.
    """
    result = ""
    # 1. specific command required by the user
    command_to_run = "sudo /usr/bin/systemctl poweroff"

    # 2. Verify 'at' is installed on the system
    if not shutil.which("at"):
        result = "Error: The 'at' command is not found. Please install it (e.g., sudo apt install at)."
        logger.error(result)
        return result

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
        result = f"Success: {process.stderr.decode('utf-8').strip()}"
        logger.info(result)
    except subprocess.CalledProcessError as e:
        # Handle errors (e.g., user is not root, or syntax error)
        result = f"Error: failed to schedule shutdown. \n{e.stderr.decode('utf-8')}"
        logger.error(result)
    except PermissionError:
        result = "Error: failed to schedule shutdown. You need sudo privileges to schedule this command."
        logger.error(result)

    return result


def main():
    username = os.environ.get("BOARD_USERNAME")
    password = os.environ.get("BOARD_PASSWORD")
    base_url = os.environ.get("BOARD_BASE_URL", "http://127.0.0.1:5000")

    if not username or not password:
        logger.error("BOARD_USERNAME and BOARD_PASSWORD environment variables must be set.")
        return

    client = MessageBoardClient(base_url=base_url)
    logger.info("Automated Message Board Monitor start")

    while True:
        try:
            if not client.token:
                success, _ = client.login(username, password)
                if not success:
                    logger.error("Failed to login to monitor.")
                    time.sleep(60)
                    continue

            private_messages = client.get_private_messages()
            if isinstance(private_messages, list):
                for a_message in private_messages:
                    sender = a_message.get('sender_username', '')
                    content = a_message.get('content', '')
                    if sender == 'daniel' and content == 'shutdown':
                        logger.warning("Shutdown command received!")
                        schedule_shutdown()
                        # Optional: delete the message here so it doesn't loop

        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}")

        # Wait 60 seconds before checking again
        time.sleep(60)

if __name__ == "__main__":
    main()


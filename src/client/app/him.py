# client_app/him.py
# Human Interface of MessageBoardClient
# Ensure the server is running before executing this.
# You'll need to create users using 'manage_db.py' first.
from client import MessageBoardClient
from getpass import getpass # For securely getting password input

def main():
    client = MessageBoardClient(base_url="https://danielwaltherberns.pythonanywhere.com/") # Adjust if server runs elsewhere

    print("Message Board Human Interface")
    print("------------------------")

    while True:
        if not client.token:
            print("\nYou are not logged in.")
            username = input("Enter username to login: ")
            password = getpass("Enter password: ")
            success, _ = client.login(username, password)
            if not success:
                continue # Try login again or exit
        
        current_username = username # Store username for display after login
        print(f"\nLogged in as: {current_username}")
        print("\nAvailable actions:")
        print("1. Send Private Message")
        print("2. Send Group Message")
        print("3. Send Public Message")
        print("4. Get My Private Messages")
        print("5. Get My Group Messages")
        print("6. Get Public Messages (subscribed or all/filtered)")
        print("7. Subscribe to Tags")
        print("8. Unsubscribe from Tags")
        print("9. Delete a Message")
        print("10. Get Server Status (Admin Only)")
        print("11. DELETE ALL MESSAGES (Admin Only)")
        print("12. Logout")
        print("0. Exit")
        _input = input("Enter your choice: ")
        try:
            choice = int(_input)
        except Exception:
            choice = 0
        try:
            match choice:
                case 1:
                    recipient = input("Recipient username: ")
                    content = input("Message content: ")
                    print(client.send_private_message(recipient, content))
                case 2:
                    recipients_str = input("Recipient usernames (comma-separated): ")
                    recipients = [r.strip() for r in recipients_str.split(',')]
                    content = input("Message content: ")
                    print(client.send_group_message(recipients, content))
                case 3:
                    content = input("Message content: ")
                    tags_str = input("Tags (comma-separated, optional): ")
                    tags = [t.strip() for t in tags_str.split(',')] if tags_str else []
                    print(client.send_public_message(content, tags))
                case 4:
                    print(client.get_private_messages())
                case 5:
                    print(client.get_group_messages())
                case 6:
                    tags_str = input("Filter by tags (comma-separated, optional, press Enter for subscribed/all): ")
                    filter_tags = [t.strip() for t in tags_str.split(',')] if tags_str else None
                    public_messages = client.get_public_messages(filter_tags=filter_tags)
                    for number, pm in enumerate(public_messages):
                        print(f"{number}.")
                        if isinstance(pm, dict):
                            for key, value in pm.items():
                               print(f"    {key}: {value}")
                        else:
                            print(pm)
                case 7:
                    tags_str = input("Tags to subscribe to (comma-separated): ")
                    tags = [t.strip() for t in tags_str.split(',')]
                    print(client.subscribe_to_tags(tags))
                case 8:
                    tags_str = input("Tags to unsubscribe from (comma-separated): ")
                    tags = [t.strip() for t in tags_str.split(',')]
                    print(client.unsubscribe_from_tags(tags))
                case 9:
                    message_id = int(input("Message ID to delete: "))
                    print(client.delete_message(message_id))
                case 10:
                    print(client.get_server_status())
                case 11:
                    confirmation = input("This is an irreversible action. To confirm, type 'delete all messages': ")
                    if confirmation == "delete all messages":
                        print(client.delete_all_messages(confirmation))
                    else:
                        print("Confirmation incorrect. Action aborted.")
                case 12:
                    client.logout()
                    username = None # Clear username after logout
                case 0:
                    if client.token:
                        client.logout() # Attempt logout before exiting
                    print("Exiting client.")
                    break
                case _:
                    print("Invalid choice. Please try again.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()


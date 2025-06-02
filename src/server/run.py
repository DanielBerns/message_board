# run.py
# This file is used to run the Flask development server.
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from app import create_app

# Create the Flask app instance using the app factory
# It will look for FLASK_CONFIG in environment variables, defaulting to 'development'
config_name = os.getenv('FLASK_CONFIG', 'development')
app = create_app(config_name)

if __name__ == '__main__':
    # Run the app
    # Host '0.0.0.0' makes the server accessible externally
    # Debug mode should be False in production
    app.run(host='0.0.0.0', port=5000, debug=app.config.get('DEBUG', False))


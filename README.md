# WebScanner

## Description
WebScanner is a Django-based web application designed to perform web scanning and data extraction tasks. It leverages powerful libraries such as BeautifulSoup and Requests to facilitate web scraping and scanning functionalities. This project provides a clean and modular structure for building and extending web scanning capabilities.

## Features
- Web scanning and data extraction
- User-friendly web interface built with Django
- SQLite database for storing scan results
- Modular app structure for easy customization and extension

## Tech Stack
- Python 3.x
- Django 5.0+
- SQLite (default database)
- BeautifulSoup4
- Requests
- python-dotenv

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd webscan
   ```

2. (Optional but recommended) Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install the required dependencies:
   ```bash
   pip install -r WebScanner/requirements.txt
   ```

4. Apply database migrations:
   ```bash
   python WebScanner/manage.py migrate
   ```

## Usage

1. Run the development server:
   ```bash
   python WebScanner/manage.py runserver
   ```

2. Open your browser and navigate to:
   ```
   http://127.0.0.1:8000/
   ```

3. Use the web interface to perform scans and view results.

## Project Structure

```
/webscan
│
├── WebScanner/                  # Django project folder
│   ├── scanner/                 # Main app for scanning functionality
│   │   ├── migrations/          # Database migrations
│   │   ├── static/              # Static files (CSS, JS)
│   │   ├── templates/           # HTML templates
│   │   ├── utils/               # Utility modules
│   │   ├── admin.py
│   │   ├── apps.py
│   │   ├── models.py
│   │   ├── urls.py
│   │   ├── views.py
│   │   └── tests.py
│   ├── WebScanner/              # Project settings and configuration
│   │   ├── settings.py
│   │   ├── urls.py
│   │   ├── wsgi.py
│   │   └── asgi.py
│   ├── db.sqlite3               # SQLite database file
│   └── manage.py                # Django management script
│
├── flask_template/              # Flask template (separate from WebScanner)
│
├── README.md                   # This file
├── .gitignore
└── requirements.txt            # (if present, for root dependencies)
```

## Contributing
Contributions are welcome! Please fork the repository and submit pull requests for any improvements or bug fixes.

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Contact
For questions or support, please contact the project maintainer.

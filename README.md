
# Security-Enhanced Django Project

This project demonstrates the implementation of multiple security features in a Django application, focusing on enhancing authentication, access control, and protection against common web attacks.

## Features Implemented

-   **Multi-Factor Authentication (MFA)**: Adds an extra layer of security by requiring multiple forms of verification.
-   **Captcha**: Prevents automated bots from accessing the application.
-   **OAuth**: Enables secure, token-based authentication using third-party providers.
-   **Single Sign-On (SSO)**: Allows users to authenticate once and access multiple applications.
-   **DDoS Protection**: Basic measures to detect and mitigate distributed denial-of-service attacks.
-   **"Remember Me" Functionality**: Allows users to stay logged in across sessions.
-   **Throttling and Rate Limiting**: Protects the API from excessive usage and abuse.

## Requirements

-   Python 3.x
-   Django
-   djangorestframework
-   django-axes (for DDoS protection)
-   django-simple-captcha
-   django-oauth-toolkit
-   django-allauth (for OAuth and SSO)

## Installation

1.  **Clone the repository**

```bash
git clone <your-repo-url>
cd <your-repo-directory>

```

2.  **Create a virtual environment and activate it**

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows, use venv\Scripts\activate

```

3.  **Install the dependencies**

```bash
pip install -r requirements.txt

```

## Running the Server

```bash
python manage.py runserver

```

By default, the server will start at `http://127.0.0.1:8000`.

## Usage

### Multi-Factor Authentication

-   Enabled during the login process with an OTP sent to the user's email or mobile.

### Captcha

-   Integrated into the login and registration forms to prevent automated access.

### OAuth and SSO

-   Configured with popular providers (Google, Facebook, etc.).
-   SSO enabled for internal applications.

### DDoS Protection

-   Basic protection implemented using request throttling and django-axes.

### "Remember Me"

-   Checkbox option in the login form to keep users logged in.

### Throttling and Rate Limiting

-   Configured for API endpoints using Django REST Framework's throttling classes.

## Testing the API

You can test the API using tools like:

-   [Postman](https://www.postman.com/)
-   `curl`
-   Browsable API interface at `http://127.0.0.1:8000/api/`

### Example Using Curl

```bash
curl -X GET http://127.0.0.1:8000

```

### Example Using Requests in Python

```python
import requests
response = requests.get("http://127.0.0.1:8000")
print(response.json())

```

## Note

-   Replace `'127.0.0.1:8000'` with your actual API URL if different.
-   Ensure the server is running before sending requests.

## License

This project is licensed under the MIT License.

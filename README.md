# Auth-Register-Django

This project is a basic authentication system using Django REST Framework, JWT tokens, and HTML-based user interfaces. It allows users to register, log in using username or email, and access a protected profile page via token-based authentication.

---

## 🔧 Features

- User registration (username, email, password)
- Login with either **username or email**
- Passwords hashed using `bcrypt`
- JWT-based authentication (access + refresh tokens)
- HTML views for:
  - Register
  - Login
  - Logout
  - Protected profile (only accessible with valid JWT)
- JWT token stored in **HttpOnly cookie**

---

## 📁 Project Structure

```
Auth-Register-Django/
├── accounts/
│   ├── views.py
│   ├── serializers.py
│   ├── urls.py
│   └── templates/accounts/
│       ├── register.html
│       ├── login.html
|       ├── logout.html
│       └── profile.html
├── Auth-Register-Django/
│   ├── settings.py
│   └── urls.py
├── manage.py
```

---

## 🛠 Setup Instructions

### 1. Clone the repository

```bash
git clone https://github.com/Makihataima-Ken/Auth-Register-Django.git
cd  Auth-Register-Django
```

### 2. Create and activate a virtual environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

Make sure the following packages are included:
- `Django`
- `djangorestframework`
- `djangorestframework-simplejwt`
- `bcrypt`

### 4. Migrate database

```bash
python manage.py migrate
```

### 5. Run the server

```bash
python manage.py runserver
```

---

## 🧪 How to Test

### 🔐 Login & Register (HTML)

- Visit `http://localhost:8000/register/` — create an account
- Visit `http://localhost:8000/login/` — login and receive a JWT token in a cookie
- Visit `http://localhost:8000/logout/` — logout
- Visit `http://localhost:8000/profile/` — view protected profile info

### 🧪 API Testing with Postman

- Send a `POST` to `/login/` with:
  ```json
  {
    "username_or_email": "your_username_or_email",
    "password": "your_password"
  }
  ```

- Receive `access` and `refresh` JWT tokens
- Access protected API views with:
  ```
  Authorization: Bearer <access_token>
  ```

---

## 🔐 Security Notes

- JWT access token is stored in a **secure HttpOnly cookie**
- Passwords are hashed with **bcrypt**
- Profile view is protected via token verification
- CSRF protection can be added for more advanced setups

---

## 📄 License

This project is licensed under the MIT License.

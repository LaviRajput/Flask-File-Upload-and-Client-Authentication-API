
# Flask File Upload and Client Authentication API

This project provides a secure file upload and user authentication system using Flask. It supports two user roles: **Client Users** and **Ops Users**, with JWT-based authentication and encrypted file URLs.

## Features

- JWT Authentication for Ops and Client users
- File uploads by Ops users
- Secure file download and listing for Client users
- Client signup and email verification (simulated)
- Encrypted download URLs using Fernet

## Base URL

```
http://127.0.0.1:5000
```

---

## 📌 Endpoints

### 🔹 Client API

#### 1. Client Signup

**POST** `/client/signup`

**Request:**
```json
{
  "email": "client_user@example.com",
  "password": "password"
}
```

**Response:**
```json
{
  "msg": "User signed up successfully",
  "encrypted_url": "<encrypted_url>"
}
```

---

#### 2. Verify Email

**POST** `/client/verify-email`

**Request:**
```json
{
  "email": "client_user@example.com"
}
```

**Response:**
```json
{
  "msg": "Verification email sent to client_user@example.com"
}
```

---

#### 3. Client Login

**POST** `/client/login`

**Request:**
```json
{
  "email": "client_user@example.com",
  "password": "password"
}
```

**Response:**
```json
{
  "access_token": "<JWT token>"
}
```

---

#### 4. List Files

**GET** `/client/files`  
🔒 Requires JWT Token in Authorization header.

**Response:**
```json
{
  "files": ["file1.pptx", "file2.xlsx"]
}
```

---

#### 5. Download File

**GET** `/client/download/<filename>`  
🔒 Requires JWT Token.

**Response:**
```json
{
  "download_url": "<encrypted_download_url>"
}
```

---

### 🔸 Ops API

#### 6. Ops Login

**POST** `/ops/login`

**Request:**
```json
{
  "username": "ops_user",
  "password": "password"
}
```

**Response:**
```json
{
  "access_token": "<JWT token>"
}
```

---

#### 7. Upload File

**POST** `/ops/upload`  
🔒 Requires JWT Token in Authorization header.

**Form-Data:**
- `file`: (Choose a .pptx, .docx, or .xlsx file)

**Response:**
```json
{
  "msg": "File uploaded successfully"
}
```

---

## ⚙️ Setup Instructions

### 1. Install Dependencies
```bash
pip install Flask flask-jwt-extended cryptography
```

### 2. Run the Flask App
```bash
python app.py
```

---

## 📁 Project Structure

```
.
├── app.py
├── uploads/
└── README.md
```


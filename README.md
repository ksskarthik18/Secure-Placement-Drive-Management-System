# Secure Placement Drive Management System (SPDMS)

A full-stack Flask application designed to demonstrate core Cyber Security concepts:
- **Authentication**: MFA (OTP), Salted Hashing (bcrypt).
- **Access Control**: RBAC (Student, HR, Admin).
- **Confidentiality**: AES-256 Encryption (Resumes).
- **Integrity**: Digital Signatures (SHA-256 + RSA).
- **Theory**: Security Levels and Attack Countermeasures.

## Requirements
- Python 3.8+
- SQLite (Built-in)

## Installation

1.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

2.  **Initialize Database**:
    ```bash
    python init_db.py
    ```

## Running the Application

1.  **Start the Server**:
    ```bash
    python run.py
    ```

2.  **Access the App**:
    Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

## Demonstration Guide (For Evaluator)

### 1. Registration & Authentication
- Register a **Student** (`student1` / `pass123`)
- Register an **HR** (`hr1` / `pass123`)
- Register an **Admin** (`admin1` / `pass123`)
- Login and key in the OTP displayed in the **Server Console** (or check the flash message if enabled).

### 2. Student Flow (Encryption)
- Login as **Student**.
- Go to "Upload Encrypted Resume".
- Upload a file.
- Observe "Encrypt & Upload" action. The file is stored as ciphertext in `site.db`.

### 3. HR Flow (Decryption & Signing)
- Login as **HR**.
- **Post a Job**.
- Go to **Review Applicants**.
- View the **Decrypted Resume** (demonstrates authorized decryption).
- **Publish Result**: Enter salary package.
- This triggers **Digital Signing** (SHA-256 Hash -> RSA Sign).

### 4. Admin Flow (Verification)
- Login as **Admin**.
- **Password Hashes**: View the `User` table to see bcrypt hashes.
- **RBAC Matrix**: View the permissions table.
- **Encryption Demo**: Use the interactive tool to encrypt bits of text.
- **Theory**: Present the security concepts.

## Tech Stack
- **Backend**: Flask
- **Database**: SQLite, SQLAlchemy
- **Crypto**: PyCryptodome, Bcrypt
- **Frontend**: Vanilla CSS (Modern Dark Mode supported)

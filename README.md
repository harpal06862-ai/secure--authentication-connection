# Secure Authentication System

A secure login system built with Flask, JWT, bcrypt and PostgreSQL.

## Features
- User registration and login
- Passwords hashed with bcrypt
- JWT access tokens that expire in 15 minutes
- Refresh tokens in HttpOnly cookies, rotated on every use
- Protected API route and session management (logout, logout everywhere)
- Account lock after 5 failed login attempts

## Technologies
Python (Flask, PyJWT, bcrypt), PostgreSQL, HTML/CSS/JavaScript

## How to run
1. Install packages: `pip install -r requirements.txt`
2. Create a PostgreSQL database named `authdb`
3. Copy `.env.example` to `.env` and fill in DATABASE_URL and JWT_SECRET
4. Create tables: `flask --app app init-db`
5. Start the app: `python app.py`
6. Open http://localhost:5000

## Author
Harpal Singh

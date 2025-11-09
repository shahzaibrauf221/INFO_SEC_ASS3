#!/usr/bin/env python3
"""
Setup MySQL database for secure chat
"""
import pymysql
from dotenv import load_dotenv
import os

load_dotenv()

def setup_database():
    # Connect to MySQL
    connection = pymysql.connect(
        host=os.getenv('DB_HOST', 'localhost'),
        user=os.getenv('DB_USER', 'root'),
        password=os.getenv('DB_PASSWORD', ''),
    )
    
    try:
        with connection.cursor() as cursor:
            # Create database
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {os.getenv('DB_NAME', 'securechat')}")
            cursor.execute(f"USE {os.getenv('DB_NAME', 'securechat')}")
            
            # Create users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    salt VARBINARY(16) NOT NULL,
                    pwd_hash CHAR(64) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            connection.commit()
            print("✓ Database setup completed successfully!")
            print(f"  - Database: {os.getenv('DB_NAME', 'securechat')}")
            print("  - Table: users")
            
    finally:
        connection.close()

if __name__ == "__main__":
    setup_database()

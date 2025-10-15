import os
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
import bcrypt
import asyncio

# Load environment variables from .env file
load_dotenv()

async def create_user(email: str, password: str, name: str, role: str = "Viewer"):
    mongo_uri = os.getenv("MONGO_URI")
    if not mongo_uri:
        print("❌ MONGO_URI not found in .env file")
        return

    try:
        # Create MongoDB client
        client = AsyncIOMotorClient(mongo_uri)
        db = client[os.getenv("DB_NAME", "asset_management")]

        # Check if the user already exists
        existing_user = await db["users"].find_one({"email": email})
        if existing_user:
            print("❌ User already exists with this email.")
            return

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Create the user
        new_user = {
            "email": email,
            "password": hashed_password.decode('utf-8'),
            "name": name,
            "role": role,
        }
        await db["users"].insert_one(new_user)
        print("✅ New user created successfully!")

    except Exception as e:
        print("❌ Error while creating user:", e)
    finally:
        client.close()
        print("✅ MongoDB connection closed.")

async def test_credentials(email: str, password: str):
    mongo_uri = os.getenv("MONGO_URI")
    if not mongo_uri:
        print("❌ MONGO_URI not found in .env file")
        return

    try:
        # Create MongoDB client
        client = AsyncIOMotorClient(mongo_uri)
        db = client[os.getenv("DB_NAME", "asset_management")]

        # Query the user by email
        user = await db["users"].find_one({"email": email})
        if not user:
            print("❌ User not found")
            return

        # Verify the password
        if bcrypt.checkpw(password.encode('utf-8'), user["password"].encode('utf-8')):
            print("✅ Credentials are valid!")
        else:
            print("❌ Invalid password")

    except Exception as e:
        print("❌ Error while checking credentials:", e)
    finally:
        client.close()
        print("✅ MongoDB connection closed.")

# Run the script
if __name__ == "__main__":
    action = input("Enter 'create' to create a new user or 'test' to test credentials: ").strip().lower()

    if action == "create":
        email = input("Enter email: ").strip()
        password = input("Enter password: ").strip()
        name = input("Enter name: ").strip()
        role = input("Enter role (Admin/Editor/Viewer, default is Viewer): ").strip() or "Viewer"
        asyncio.run(create_user(email, password, name, role))
    elif action == "test":
        email = input("Enter email: ").strip()
        password = input("Enter password: ").strip()
        asyncio.run(test_credentials(email, password))
    else:
        print("❌ Invalid action. Please enter 'create' or 'test'.")
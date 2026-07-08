from pymongo import MongoClient
import os
import logging
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
import bcrypt

load_dotenv()
logger = logging.getLogger(__name__)

MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    raise RuntimeError("MONGO_URI not found in .env")

client = MongoClient(MONGO_URI)
db = client["svfc_pos"]

bills_col = db["bills"]
counter_col = db["counters"]
users_col = db["users"]
custom_items_col = db["custom_items"]
custom_categories_col = db["custom_categories"]

BUSINESS_TZ = timezone(timedelta(hours=5, minutes=30))

def business_now():
    return datetime.now(BUSINESS_TZ)

def setup_database_indexes():
    try:
        bills_col.create_index([("createdAt", -1)])
        bills_col.create_index([("token", -1)])
        bills_col.create_index([("deleted", 1)])
        bills_col.create_index([("createdAtISO", -1)])
        users_col.create_index([("email", 1)])
        custom_items_col.create_index([("name", 1)])
        custom_categories_col.create_index([("name", 1)])
        logger.info("✅ MongoDB database indexes ensured")
    except Exception as e:
        logger.warning(f"Could not create database indexes: {str(e)}")

def hash_password(password):
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

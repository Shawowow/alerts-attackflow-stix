from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
import os

username = os.environ['$MONGODB_USERNAME']
password = os.environ['$MONGODB_PASSWORD']
uri = f"mongodb://{username}:{password}localhost:27017/"
try:   
    client = MongoClient(uri)
except ConnectionFailure as e:
    raise ConnectionFailure(f"Could not connect to MongoDB: {e}")
database = MongoClient.get_database("rcti") 

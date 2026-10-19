import logging
import os

from pymongo import MongoClient
import psycopg2

log = logging.getLogger(__name__)

# rempart-expect: DATA-CONNECTION-STRING-CREDS
client = MongoClient("mongodb://admin:Pr0d-Passw0rd-91@mongo.internal:27017/app")
# rempart-safe: DATA-CONNECTION-STRING-CREDS
client2 = MongoClient(os.environ["MONGO_URL"])
# rempart-expect: DATA-TLS-DISABLED
pg = psycopg2.connect("host=db.internal dbname=app user=app sslmode=disable")


def login(user, password):
    # rempart-expect: DATA-SENSITIVE-LOGGED
    log.info("login attempt user=%s password=%s", user, password)
    # rempart-safe: DATA-SENSITIVE-LOGGED
    log.info("login attempt user=%s", user)

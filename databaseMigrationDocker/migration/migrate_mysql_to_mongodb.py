import pymysql
from pymongo import MongoClient

# MySQL connection
mysql_conn = pymysql.connect(
    host='mysql_db',
    user='testuser',
    password='testpassword',
    database='testdb',
    port=3306
)

# MongoDB connection
mongo_client = MongoClient('mongodb://mongodb:27017/')
mongo_db = mongo_client['testdb']
mongo_collection = mongo_db['testcollection']

try:
    with mysql_conn.cursor() as cursor:
        cursor.execute("SELECT * FROM testtable")
        rows = cursor.fetchall()

        documents = [
            {'id': row[0], 'name': row[1], 'value': row[2]}
            for row in rows
        ]
        if documents:
            mongo_collection.insert_many(documents)
        print("Data migrated from MySQL to MongoDB successfully.")
finally:
    mysql_conn.close()
    mongo_client.close()

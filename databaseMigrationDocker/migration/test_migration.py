import pymysql
from pymongo import MongoClient
from py2neo import Graph

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

# Neo4j connection
graph = Graph("bolt://neo4j_db:7687", auth=("neo4j", "testpassword"))

try:
    with mysql_conn.cursor() as cursor:
        cursor.execute("SELECT * FROM testtable")
        mysql_rows = cursor.fetchall()

        mongo_docs = list(mongo_collection.find({}, {'_id': 0}))
        neo4j_nodes = graph.run("MATCH (n:TestNode) RETURN n.id AS id, n.name AS name, n.value AS value").data()

        # Verify data in MongoDB
        for row in mysql_rows:
            id, name, value = row
            doc = next((d for d in mongo_docs if d['id'] == id), None)
            assert doc is not None, f"Document with id {id} not found in MongoDB"
            assert doc['name'] == name, f"Name mismatch for id {id} in MongoDB"
            assert doc['value'] == value, f"Value mismatch for id {id} in MongoDB"

        # Verify data in Neo4j
        for row in mysql_rows:
            id, name, value = row
            node = next((n for n in neo4j_nodes if n['id'] == id), None)
            assert node is not None, f"Node with id {id} not found in Neo4j"
            assert node['name'] == name, f"Name mismatch for id {id} in Neo4j"
            assert node['value'] == value, f"Value mismatch for id {id} in Neo4j"

        print("All data verified successfully.")
finally:
    mysql_conn.close()
    mongo_client.close()

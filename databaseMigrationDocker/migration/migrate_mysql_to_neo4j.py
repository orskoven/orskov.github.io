import pymysql
from py2neo import Graph, Node

# MySQL connection
mysql_conn = pymysql.connect(
    host='mysql_db',
    user='testuser',
    password='testpassword',
    database='testdb',
    port=3306
)

# Neo4j connection
graph = Graph("bolt://neo4j_db:7687", auth=("neo4j", "testpassword"))

try:
    with mysql_conn.cursor() as cursor:
        cursor.execute("SELECT * FROM testtable")
        rows = cursor.fetchall()

        for row in rows:
            node = Node("TestNode", id=row[0], name=row[1], value=row[2])
            graph.merge(node, "TestNode", "id")
        print("Data migrated from MySQL to Neo4j successfully.")
finally:
    mysql_conn.close()

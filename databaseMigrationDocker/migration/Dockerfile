FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt
RUN pip install cryptography
RUN pip install pymysql py2neo

COPY migrate_mysql_to_mongodb.py .
COPY migrate_mysql_to_neo4j.py .
COPY migrate_mysql_to_neo4j_FULLRBAC.py .
COPY test_migration.py .
COPY run_migrations.sh .

RUN chmod +x run_migrations.sh

CMD ["./run_migrations.sh"]

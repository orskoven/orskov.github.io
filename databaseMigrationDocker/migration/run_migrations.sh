#!/bin/sh
python migrate_mysql_to_mongodb.py
python migrate_mysql_to_neo4j.py
python migrate_mysql_to_neo4j_FULLRBAC.py
python test_migration.py

import pymysql
from py2neo import Graph, Node, Relationship

# MySQL connection
mysql_conn = pymysql.connect(
    host='mysql_db',
    user='testuser',
    password='testpassword',
    database='testdb',
    port=3306,
    cursorclass=pymysql.cursors.DictCursor  # Allows fetching rows as dictionaries
)

# Neo4j connection
graph = Graph("bolt://neo4j_db:7687", auth=("neo4j", "testpassword"))

try:
    with mysql_conn.cursor() as cursor:
        # Migrate users
        print("Migrating users...")
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
        user_nodes = {}
        for user in users:
            user_node = Node(
                "User",
                user_id=user['user_id'],
                username=user['username'],
                password_hash=user['password_hash'],
                email_encrypted=user['email_encrypted'].decode('utf-8', 'ignore'),
                consent_status=user['consent_status'],
                created_at=user['created_at'],
                updated_at=user['updated_at']
            )
            graph.merge(user_node, "User", "user_id")
            user_nodes[user['user_id']] = user_node
        print(f"Migrated {len(users)} users.")

        # Migrate roles
        print("Migrating roles...")
        cursor.execute("SELECT * FROM roles")
        roles = cursor.fetchall()
        role_nodes = {}
        for role in roles:
            role_node = Node(
                "Role",
                role_id=role['role_id'],
                role_name=role['role_name'],
                description=role['description']
            )
            graph.merge(role_node, "Role", "role_id")
            role_nodes[role['role_id']] = role_node
        print(f"Migrated {len(roles)} roles.")

        # Migrate permissions
        print("Migrating permissions...")
        cursor.execute("SELECT * FROM permissions")
        permissions = cursor.fetchall()
        permission_nodes = {}
        for permission in permissions:
            permission_node = Node(
                "Permission",
                permission_id=permission['permission_id'],
                permission_name=permission['permission_name'],
                description=permission['description']
            )
            graph.merge(permission_node, "Permission", "permission_id")
            permission_nodes[permission['permission_id']] = permission_node
        print(f"Migrated {len(permissions)} permissions.")

        # Migrate user_roles relationships
        print("Migrating user_roles relationships...")
        cursor.execute("SELECT * FROM user_roles")
        user_roles = cursor.fetchall()
        for ur in user_roles:
            user_node = user_nodes.get(ur['user_id'])
            role_node = role_nodes.get(ur['role_id'])
            if user_node and role_node:
                rel = Relationship(user_node, "HAS_ROLE", role_node)
                graph.merge(rel)
        print(f"Migrated {len(user_roles)} user_roles relationships.")

        # Migrate role_permissions relationships
        print("Migrating role_permissions relationships...")
        cursor.execute("SELECT * FROM role_permissions")
        role_permissions = cursor.fetchall()
        for rp in role_permissions:
            role_node = role_nodes.get(rp['role_id'])
            permission_node = permission_nodes.get(rp['permission_id'])
            if role_node and permission_node:
                rel = Relationship(role_node, "HAS_PERMISSION", permission_node)
                graph.merge(rel)
        print(f"Migrated {len(role_permissions)} role_permissions relationships.")

        # Migrate followers relationships
        print("Migrating followers relationships...")
        cursor.execute("SELECT * FROM followers")
        followers = cursor.fetchall()
        for follower in followers:
            user_node = user_nodes.get(follower['user_id'])
            follower_node = user_nodes.get(follower['follower_user_id'])
            if user_node and follower_node:
                rel = Relationship(follower_node, "FOLLOWS", user_node, followed_at=follower['followed_at'])
                graph.merge(rel)
        print(f"Migrated {len(followers)} follower relationships.")

        # Migrate posts
        print("Migrating posts...")
        cursor.execute("SELECT * FROM posts")
        posts = cursor.fetchall()
        post_nodes = {}
        for post in posts:
            user_node = user_nodes.get(post['user_id'])
            if user_node:
                post_node = Node(
                    "Post",
                    post_id=post['post_id'],
                    content=post['content'],
                    created_at=post['created_at'],
                    updated_at=post['updated_at']
                )
                graph.merge(post_node, "Post", "post_id")
                rel = Relationship(user_node, "CREATED", post_node)
                graph.merge(rel)
                post_nodes[post['post_id']] = post_node
        print(f"Migrated {len(posts)} posts.")

        # Migrate comments
        print("Migrating comments...")
        cursor.execute("SELECT * FROM comments")
        comments = cursor.fetchall()
        comment_nodes = {}
        for comment in comments:
            user_node = user_nodes.get(comment['user_id'])
            post_node = post_nodes.get(comment['post_id'])
            if user_node and post_node:
                comment_node = Node(
                    "Comment",
                    comment_id=comment['comment_id'],
                    content=comment['content'],
                    created_at=comment['created_at']
                )
                graph.merge(comment_node, "Comment", "comment_id")
                rel_user_comment = Relationship(user_node, "WROTE", comment_node)
                rel_comment_post = Relationship(comment_node, "COMMENTS_ON", post_node)
                graph.merge(rel_user_comment)
                graph.merge(rel_comment_post)
                comment_nodes[comment['comment_id']] = comment_node
        print(f"Migrated {len(comments)} comments.")

        # Migrate likes relationships
        print("Migrating likes relationships...")
        cursor.execute("SELECT * FROM likes")
        likes = cursor.fetchall()
        for like in likes:
            user_node = user_nodes.get(like['user_id'])
            post_node = post_nodes.get(like['post_id'])
            if user_node and post_node:
                rel = Relationship(user_node, "LIKES", post_node, liked_at=like['liked_at'])
                graph.merge(rel)
        print(f"Migrated {len(likes)} likes relationships.")

        # Migrate messages
        print("Migrating messages...")
        cursor.execute("SELECT * FROM messages")
        messages = cursor.fetchall()
        for message in messages:
            sender_node = user_nodes.get(message['sender_id'])
            receiver_node = user_nodes.get(message['receiver_id'])
            if sender_node and receiver_node:
                message_node = Node(
                    "Message",
                    message_id=message['message_id'],
                    content=message['content'],
                    sent_at=message['sent_at']
                )
                graph.merge(message_node, "Message", "message_id")
                rel_sender = Relationship(sender_node, "SENT", message_node)
                rel_receiver = Relationship(message_node, "TO", receiver_node)
                graph.merge(rel_sender)
                graph.merge(rel_receiver)
        print(f"Migrated {len(messages)} messages.")

        # Migrate notifications
        print("Migrating notifications...")
        cursor.execute("SELECT * FROM notifications")
        notifications = cursor.fetchall()
        for notification in notifications:
            user_node = user_nodes.get(notification['user_id'])
            source_user_node = user_nodes.get(notification['source_user_id'])
            post_node = post_nodes.get(notification['post_id']) if notification['post_id'] else None
            message_id = notification['message_id']
            notification_node = Node(
                "Notification",
                notification_id=notification['notification_id'],
                type=notification['type'],
                created_at=notification['created_at'],
                is_read=bool(notification['is_read'])
            )
            graph.merge(notification_node, "Notification", "notification_id")
            if user_node:
                rel_user = Relationship(notification_node, "NOTIFIES", user_node)
                graph.merge(rel_user)
            if source_user_node:
                rel_source = Relationship(source_user_node, "TRIGGERED", notification_node)
                graph.merge(rel_source)
            if post_node:
                rel_post = Relationship(notification_node, "ABOUT_POST", post_node)
                graph.merge(rel_post)
            if message_id:
                # Fetch the message node if it exists
                message_node = graph.nodes.match("Message", message_id=message_id).first()
                if message_node:
                    rel_message = Relationship(notification_node, "ABOUT_MESSAGE", message_node)
                    graph.merge(rel_message)
        print(f"Migrated {len(notifications)} notifications.")

        # Migrate audit logs (optional)
        # Implement similar logic if needed

        # Migrate other tables as required

        print("Data migrated from MySQL to Neo4j successfully.")

finally:
    mysql_conn.close()

import mysql.connector
import time
import uuid
import random
from datetime import datetime

# -------------------------------
# UUID7 generator for Python 3.9
# -------------------------------
def generate_uuid7():
    ts_ms = int(time.time() * 1000) & 0xFFFFFFFFFFFF  # 6 bytes timestamp
    ts_bytes = ts_ms.to_bytes(6, byteorder='big')
    rand_bytes = random.getrandbits(80).to_bytes(10, byteorder='big')  # 10 bytes random
    uuid_bytes = ts_bytes + rand_bytes
    return str(uuid.UUID(bytes=uuid_bytes))

# -------------------------------
# Database configs
# -------------------------------
OLD_DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'root',
    'database': 'sample_ums'
}

NEW_DB_NAME = "dharma"

NEW_DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'root',
}

# -------------------------------
# Full schema for new DB
# -------------------------------
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS User (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    user_uuid CHAR(36) NOT NULL UNIQUE, 
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    mail VARCHAR(150) UNIQUE,
    contact VARCHAR(15),
    password VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    password_last_updated DATETIME DEFAULT null,
    last_login_at DATETIME DEFAULT null,
    last_login_ip VARCHAR(45) DEFAULT null,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS Role (
    role_id INT AUTO_INCREMENT PRIMARY KEY,
    role_uuid CHAR(36) NOT NULL UNIQUE,
    role_name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS User_Role (
    user_id INT,
    role_id INT,
    assigned_by INT NULL,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES User(user_id) ON DELETE RESTRICT,
    FOREIGN KEY (role_id) REFERENCES Role(role_id) ON DELETE RESTRICT,
    FOREIGN KEY (assigned_by) REFERENCES User(user_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS Permissions (
    permission_id INT AUTO_INCREMENT PRIMARY KEY,
    permission_uuid CHAR(36) NOT NULL UNIQUE,
    permission_code VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS Permission_Group (
    group_id INT AUTO_INCREMENT PRIMARY KEY,
    group_uuid CHAR(36) NOT NULL UNIQUE,
    group_name VARCHAR(100) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    created_by INT NULL,
    FOREIGN KEY (created_by) REFERENCES User(user_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS Access_Point (
    access_id INT AUTO_INCREMENT PRIMARY KEY,
    access_uuid CHAR(36) NOT NULL UNIQUE,
    endpoint_path VARCHAR(255) NOT NULL,
    regex_pattern VARCHAR(255),
    method ENUM(
        'GET',
        'POST',
        'PUT',
        'DELETE',
        'PATCH',
        'HEAD',
        'OPTIONS',
        'TRACE',
        'CONNECT'
    ) NOT NULL,
    module VARCHAR(100) NOT NULL,
    is_public BOOLEAN DEFAULT FALSE,
    created_by INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES User(user_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS Access_Point_Permission_Mapping (
    id INT AUTO_INCREMENT PRIMARY KEY,
    access_id INT NOT NULL,
    permission_id INT NOT NULL,
    assigned_by INT NULL,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (access_id) REFERENCES Access_Point(access_id) ON DELETE RESTRICT,
    FOREIGN KEY (permission_id) REFERENCES Permissions(permission_id) ON DELETE RESTRICT,
    FOREIGN KEY (assigned_by) REFERENCES User(user_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS Role_Permission_Group (
    role_id INT,
    group_id INT,
    assigned_by INT NULL,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id, group_id),
    FOREIGN KEY (role_id) REFERENCES Role(role_id) ON DELETE RESTRICT,
    FOREIGN KEY (group_id) REFERENCES Permission_Group(group_id) ON DELETE RESTRICT,
    FOREIGN KEY (assigned_by) REFERENCES User(user_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS Audit_Trail (
    audit_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    audit_uuid CHAR(36) NOT NULL UNIQUE,
    user_id INT NULL,
    action_type ENUM('CREATE','UPDATE','DELETE','LOGIN','LOGOUT','ASSIGN_ROLE','ASSIGN_PERMISSION','OTHER') NOT NULL,
    entity_type VARCHAR(100) NOT NULL,
    entity_id BIGINT NULL,
    old_data JSON NULL,
    new_data JSON NULL,
    ip_address VARCHAR(45) NULL,
    description TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES User(user_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS Permission_Group_Mapping (
    permission_id INT NOT NULL,
    group_id INT NOT NULL,
    assigned_by INT NULL,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (permission_id, group_id),
    FOREIGN KEY (permission_id) REFERENCES Permissions(permission_id) ON DELETE RESTRICT,
    FOREIGN KEY (group_id) REFERENCES Permission_Group(group_id) ON DELETE RESTRICT,
    FOREIGN KEY (assigned_by) REFERENCES User(user_id) ON DELETE SET NULL
);
"""

# -------------------------------
# Ensure DB + Tables exist
# -------------------------------
tmp_conn = mysql.connector.connect(**NEW_DB_CONFIG)
tmp_cursor = tmp_conn.cursor()
tmp_cursor.execute(f"CREATE DATABASE IF NOT EXISTS {NEW_DB_NAME}")
tmp_conn.database = NEW_DB_NAME
for stmt in SCHEMA_SQL.split(";"):
    if stmt.strip():
        print(stmt)
        tmp_cursor.execute(stmt)
tmp_conn.commit()
tmp_cursor.close()
tmp_conn.close()

# -------------------------------
# Reconnect for migration
# -------------------------------
NEW_DB_CONFIG["database"] = NEW_DB_NAME
new_conn = mysql.connector.connect(**NEW_DB_CONFIG)
new_cursor = new_conn.cursor()
old_conn = mysql.connector.connect(**OLD_DB_CONFIG)
old_cursor = old_conn.cursor(dictionary=True)

# --- now your migration logic follows as before ---

now = datetime.utcnow()
# -------------------------------
# 1. Migrate Users
# -------------------------------
old_cursor.execute("SELECT * FROM user")
users = old_cursor.fetchall()
insert_user = """
INSERT INTO User (user_id,user_uuid, first_name, last_name, mail, contact, password, is_active, password_last_updated, last_login_at, last_login_ip, created_at, updated_at)
VALUES (%s,%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
"""
for u in users:
    new_cursor.execute(insert_user, (
        u['user_id'],
        generate_uuid7(),
        u['first_name'],
        u['last_name'],
        u['mail'],
        u['contact'],
        u['password'],
        bool(u['is_active']),
        None,   # password_last_updated
        None,   # last_login_at
        None,    # last_login_ip
        now,     # created_at
        now
    ))
print(f"Migrated {len(users)} users")

# -------------------------------
# 2. Migrate Roles
# -------------------------------
old_cursor.execute("SELECT * FROM role")
roles = old_cursor.fetchall()
insert_role = "INSERT INTO Role (role_id,role_uuid, role_name, created_at, updated_at) VALUES (%s,%s, %s, %s, %s)"
for r in roles:
    new_cursor.execute(insert_role, (r['role_id'],generate_uuid7(), r['role_name'], now, now))
print(f"Migrated {len(roles)} roles")

# -------------------------------
# 3. Migrate Permissions
# -------------------------------
old_cursor.execute("SELECT * FROM permissions")
perms = old_cursor.fetchall()
insert_perm = "INSERT INTO Permissions (permission_uuid, permission_id,permission_code, description, created_at, updated_at) VALUES (%s,%s, %s, %s, %s, %s)"
for p in perms:
    new_cursor.execute(insert_perm, (generate_uuid7(),p['permission_id'], p['permission_code'], p['description'], now, now))
print(f"Migrated {len(perms)} permissions")

# -------------------------------
# 4. Migrate Access Points
# -------------------------------
old_cursor.execute("SELECT * FROM access_point")
aps = old_cursor.fetchall()
insert_ap = """
INSERT INTO Access_Point (access_id,access_uuid, endpoint_path, regex_pattern, method, module, is_public, created_by, created_at, updated_at)
VALUES (%s,%s, %s, %s, %s, %s, %s, %s, %s, %s)
"""
for ap in aps:
    new_cursor.execute(insert_ap, (
        ap['access_id'],
        generate_uuid7(),
        ap['endpoint_path'],
        ap.get('regex_pattern'),
        ap['method'],
        ap['module'],
        bool(ap['is_public']),
        1,   # created_by
        now, # created_at
        now  # updated_at
    ))
print(f"Migrated {len(aps)} access points")

# -------------------------------
# 5. Migrate User_Role
# -------------------------------
old_cursor.execute("SELECT * FROM user_role")
user_roles = old_cursor.fetchall()
insert_ur = "INSERT INTO User_Role (user_id, role_id, assigned_by, assigned_at) VALUES (%s, %s, %s, %s)"
for ur in user_roles:
    assigned_by = None if ur['user_id'] == 1 else 1
    new_cursor.execute(insert_ur, (ur['user_id'], ur['role_id'], assigned_by, now))
print(f"Migrated {len(user_roles)} user-role mappings")

# -------------------------------
# 6. Migrate Access_Point_Permission_Mapping
# -------------------------------
old_cursor.execute("SELECT * FROM access_point_permission_mapping")
ap_pm = old_cursor.fetchall()
insert_ap_pm = """
INSERT INTO Access_Point_Permission_Mapping (access_id, permission_id, assigned_by, assigned_at)
VALUES (%s, %s, %s, %s)
"""
for m in ap_pm:
    new_cursor.execute(insert_ap_pm, (m['access_id'], m['permission_id'], 1, now))
print(f"Migrated {len(ap_pm)} access-permission mappings")

# -------------------------------
# 7. Migrate Permission_Group
# -------------------------------
old_cursor.execute("SELECT * FROM permission_group")
groups = old_cursor.fetchall()
insert_pg = "INSERT INTO Permission_Group (group_uuid, group_name, created_by, created_at, updated_at) VALUES (%s, %s, %s, %s, %s)"
for g in groups:
    new_cursor.execute(insert_pg, (generate_uuid7(), g['group_name'], 1, now, now))
print(f"Migrated {len(groups)} permission groups")

# -------------------------------
# 8. Migrate Role_Permission_Group
# -------------------------------
old_cursor.execute("SELECT * FROM role_permission_group")
rpg = old_cursor.fetchall()
insert_rpg = "INSERT INTO Role_Permission_Group (role_id, group_id, assigned_by, assigned_at) VALUES (%s, %s, %s, %s)"
for m in rpg:
    new_cursor.execute(insert_rpg, (m['role_id'], m['group_id'], 1, now))
print(f"Migrated {len(rpg)} role-permission group mappings")

# -------------------------------
# 9. Migrate Permission_Group_Mapping
# -------------------------------
old_cursor.execute("SELECT * FROM permission_group_mapping")
pgm = old_cursor.fetchall()
insert_pgm = """
INSERT INTO Permission_Group_Mapping (permission_id, group_id, assigned_by, assigned_at)
VALUES (%s, %s, %s, %s)
"""
for m in pgm:
    new_cursor.execute(insert_pgm, (m['permission_id'], m['group_id'], 1, now))
print(f"Migrated {len(pgm)} permission-group mappings")

# -------------------------------
# Commit and close
# -------------------------------
new_conn.commit()
old_cursor.close()
old_conn.close()
new_cursor.close()
new_conn.close()

print("All tables migrated successfully with UUID7 and UTC timestamps!")
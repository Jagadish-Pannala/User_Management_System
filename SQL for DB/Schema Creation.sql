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
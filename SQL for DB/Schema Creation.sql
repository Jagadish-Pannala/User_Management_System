DROP DATABASE IF EXISTS User_Management;
CREATE DATABASE User_Management;
USE User_Management;
 
-- Role Table
CREATE TABLE Role (
    role_id INT AUTO_INCREMENT PRIMARY KEY,
    role_name VARCHAR(100) NOT NULL
);
 
-- User Table
CREATE TABLE User (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    mail VARCHAR(150) UNIQUE,
    contact VARCHAR(15),
    password VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE
);
 
-- User Role Mapping
CREATE TABLE User_Role (
    user_id INT,
    role_id INT,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES User(user_id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES Role(role_id) ON DELETE CASCADE
);
 
-- Permissions Table
CREATE TABLE Permissions (
    permission_id INT AUTO_INCREMENT PRIMARY KEY,
    permission_code VARCHAR(100) UNIQUE NOT NULL,
    description TEXT
);
 
-- Permission Groups
CREATE TABLE Permission_Group (
    group_id INT AUTO_INCREMENT PRIMARY KEY,
    group_name VARCHAR(100) NOT NULL UNIQUE
);
 
-- Mapping Between Permissions and Groups
CREATE TABLE Permission_Group_Mapping (
    permission_id INT,
    group_id INT,
    PRIMARY KEY (permission_id, group_id),
    FOREIGN KEY (permission_id) REFERENCES Permissions(permission_id) ON DELETE CASCADE,
    FOREIGN KEY (group_id) REFERENCES Permission_Group(group_id) ON DELETE CASCADE
);
 
-- API Endpoints Table
CREATE TABLE Access_Point (
    access_id INT AUTO_INCREMENT PRIMARY KEY,
    endpoint_path VARCHAR(255) NOT NULL,
    method ENUM('GET', 'POST', 'PUT', 'DELETE') NOT NULL,
    module VARCHAR(100) NOT NULL,
    is_public BOOLEAN DEFAULT FALSE
);
CREATE TABLE Access_Point_Permission_Mapping (
    id INT AUTO_INCREMENT PRIMARY KEY,
    access_id INT NOT NULL,
    permission_id INT NOT NULL,
    FOREIGN KEY (access_id) REFERENCES Access_Point(access_id),
    FOREIGN KEY (permission_id) REFERENCES Permissions(permission_id)
);
 
-- Mapping Between Roles and Permission Groups (Updated Design)
CREATE TABLE Role_Permission_Group (
    role_id INT,
    group_id INT,
    PRIMARY KEY (role_id, group_id),
    FOREIGN KEY (role_id) REFERENCES Role(role_id) ON DELETE CASCADE,
    FOREIGN KEY (group_id) REFERENCES Permission_Group(group_id) ON DELETE CASCADE
);
select * from Access_Point_Permission_Mapping;
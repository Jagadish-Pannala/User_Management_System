USE User_Management;
 
INSERT INTO Role (role_name) VALUES

('Super Admin'),

('Admin'),

('HR'),

('General');
 
 
select * from Role;
 
INSERT INTO User (first_name, last_name, mail, contact, password) VALUES

('Alice',   'Morgan',   'alice.morgan@example.com',   '9876543210',  'Alice@123'),

('Bob',     'Smith',    'bob.smith@example.com',      '9876543211',  'Bob@123'),

('Carol',   'Johnson',  'carol.johnson@example.com',  '9876543212',  'Carol@123'),

('Dave',    'Williams', 'dave.williams@example.com',  '9876543213',  'Dave@123'),

('Eve',     'Brown',    'eve.brown@example.com',      '9876543214',  'Eve@123'),

('Frank',   'Taylor',   'frank.taylor@example.com',   '9876543215',  'Frank@123'),

('Grace',   'Hall',     'grace.hall@example.com',     '9876543216',  'Grace@123'),

('Henry',   'Adams',    'henry.adams@example.com',    '9876543217',  'Henry@123'),

('Irene',   'Lopez',    'irene.lopez@example.com',    '9876543218',  'Irene@123'); 

set SQL_SAFE_UPDATES = 0;

UPDATE User SET password = '$2b$12$8oGAZ3a4kMBNfIfDxlzia.qndR1MCbs4EamDYbuv/QRd3gd.fHDyi';

set SQL_SAFE_UPDATES = 1;
 
 
-- USER IDs refer to inserted users from 1 to 9

-- ROLE IDs: 1 = Super Admin, 2 = Admin, 3 = HR, 4 = General
 
INSERT INTO User_Role (user_id, role_id) VALUES

(1, 1), (1, 2),       -- Alice: Super Admin + Admin

(2, 2),               -- Bob: Admin

(3, 3),               -- Carol: HR

(4, 4),               -- Dave: General

(5, 3), (5, 4),       -- Eve: HR + General

(6, 4),               -- Frank: General

(7, 4),               -- Grace: General

(8, 4),               -- Henry: General

(9, 2), (9, 4);       -- Irene: Admin + General
 
 
INSERT INTO Permissions (permission_code, description) VALUES

-- User Permissions

('VIEW_USER_PUBLIC', 'View basic profile of users excluding Admin and HR'),

('VIEW_USER_ALL', 'View all users including Admin and HR'),

('EDIT_OWN_PROFILE', 'Edit own profile'),

('EDIT_ANY_USER', 'Edit any user profile'),

('ADD_USER', 'Create a new user'),

('DELETE_USER', 'Deactivate a user'),

('DEACTIVATE_OWN_PROFILE', 'Deactivate (soft-delete) own profile'),
 
-- Role Management

('VIEW_ROLE', 'View roles'),

('ADD_ROLE', 'Create a new role'),

('EDIT_ROLE', 'Edit role'),

('DELETE_ROLE', 'Delete role'),
 
-- Permission Management

('VIEW_PERMISSION', 'View permissions'),

('ADD_PERMISSION', 'Add permission'),

('EDIT_PERMISSION', 'Edit permission'),

('DELETE_PERMISSION', 'Delete permission'),
 
-- Permission Group Management

('VIEW_GROUP', 'View permission groups'),

('ADD_GROUP', 'Add permission group'),

('EDIT_GROUP', 'Edit permission group'),

('DELETE_GROUP', 'Delete permission group'),
 
-- Access Point Management

('MANAGE_ENDPOINTS', 'CRUD operations on access points');
 
select * from Permissions;
 
-- Grouping based on system features

INSERT INTO Permission_Group (group_name) VALUES

('User Management'),              -- ID 1

('Role Management'),              -- ID 2

('Permission Management'),        -- ID 3

('Permission Group Management'),  -- ID 4

('Access Point Management');      -- ID 5
 
 
-- User Management

INSERT INTO Permission_Group_Mapping (permission_id, group_id) VALUES

(1, 1), (2, 1), (3, 1), (4, 1), (5, 1), (6, 1), (7, 1);
 
-- Role Management

INSERT INTO Permission_Group_Mapping (permission_id, group_id) VALUES

(8, 2), (9, 2), (10, 2), (11, 2);
 
-- Permission Management

INSERT INTO Permission_Group_Mapping (permission_id, group_id) VALUES

(12, 3), (13, 3), (14, 3), (15, 3);
 
-- Permission Group Management

INSERT INTO Permission_Group_Mapping (permission_id, group_id) VALUES

(16, 4), (17, 4), (18, 4), (19, 4);
 
-- Access Point Management

INSERT INTO Permission_Group_Mapping (permission_id, group_id) VALUES

(20, 5);
 
INSERT INTO Permission_Group (group_name) VALUES

('General User Permissions'),     -- ID 6

('HR Tools'),                     -- ID 7

('Admin Tools'),                  -- ID 8

('Super Admin Tools');            -- ID 9
 
INSERT INTO Permission_Group_Mapping (permission_id, group_id) VALUES

(1, 6),  -- VIEW_USER_PUBLIC

(3, 6),  -- EDIT_OWN_PROFILE

(7, 6);  -- DEACTIVATE_OWN_PROFILE
 
INSERT INTO Permission_Group_Mapping (permission_id, group_id) VALUES

(1, 7),  -- VIEW_USER_PUBLIC

(4, 7);  -- EDIT_ANY_USER
 
INSERT INTO Permission_Group_Mapping (permission_id, group_id) VALUES

(1, 8), (2, 8), (3, 8), (4, 8), (5, 8), (6, 8), (7, 8),

(8, 8), (9, 8), (10, 8), (11, 8),

(12, 8), (13, 8), (14, 8), (15, 8),

(16, 8), (17, 8), (18, 8), (19, 8);
 
INSERT INTO Permission_Group_Mapping (permission_id, group_id) VALUES

(20, 9);  -- MANAGE_ENDPOINTS
 
 
 
-- General user

INSERT INTO Role_Permission_Group (role_id, group_id) VALUES

(4, 6);  -- General User Permissions
 
-- HR

INSERT INTO Role_Permission_Group (role_id, group_id) VALUES

(3, 6), (3, 7);  -- General + HR Tools
 
-- Admin

INSERT INTO Role_Permission_Group (role_id, group_id) VALUES

(2, 6), (2, 7), (2, 8);  -- General + HR + Admin Tools
 
-- Super Admin

INSERT INTO Role_Permission_Group (role_id, group_id) VALUES

(1, 6), (1, 7), (1, 8), (1, 9);  -- All tools
 


INSERT INTO Access_Point (endpoint_path, method, module, is_public) VALUES
('/auth/', 'GET', 'Auth Management', TRUE),
('/auth/register', 'POST', 'Auth Management', TRUE),
('/auth/login', 'POST', 'Auth Management', TRUE),
('/auth/forgot-password/{email}', 'GET', 'Auth Management', TRUE),
('/auth/forgot-password', 'POST', 'Auth Management', TRUE);


 
INSERT INTO Access_Point (endpoint_path, method, module, is_public) VALUES
('/general_user/profile/{email}', 'GET', 'General User Management', FALSE),
('/general_user/profile/{email}', 'PUT', 'General User Management', FALSE),
('/general_user/search', 'GET', 'General User Management', FALSE),
('/general_user/search/suggestions', 'GET', 'General User Management', FALSE);

INSERT INTO Access_Point_Permission_Mapping (access_id, permission_id) VALUES

-- View own profile

(6, 1),  -- VIEW_USER_PUBLIC

-- Edit own profile

(7, 3),  -- EDIT_OWN_PROFILE

-- Search other users (basic)

(8, 1),  -- VIEW_USER_PUBLIC

(9, 1);  -- VIEW_USER_PUBLIC

 
INSERT INTO Access_Point (endpoint_path, method, module, is_public) VALUES
('/admin/users/', 'GET', 'Admin - User Management', FALSE),
('/admin/users', 'GET', 'Admin - User Management', FALSE),
('/admin/users', 'POST', 'Admin - User Management', FALSE),
('/admin/users/{user_id}', 'GET', 'Admin - User Management', FALSE),
('/admin/users/{user_id}', 'PUT', 'Admin - User Management', FALSE),
('/admin/users/{user_id}', 'DELETE', 'Admin - User Management', FALSE),
('/admin/users/{user_id}/role', 'PUT', 'Admin - User Management', FALSE),
('/admin/users/{user_id}/roles', 'GET', 'Admin - User Management', FALSE);

INSERT INTO Access_Point_Permission_Mapping (access_id, permission_id) VALUES

(10, 2),  -- VIEW_USER_ALL

(11, 2),  -- VIEW_USER_ALL

(12, 5),  -- ADD_USER

(13, 2),  -- VIEW_USER_ALL

(14, 4),  -- EDIT_ANY_USER

(15, 6),  -- DELETE_USER

(16, 10), -- EDIT_ROLE

(17, 8);  -- VIEW_ROLE

-- Admin - Role Management


INSERT INTO Access_Point (endpoint_path, method, module, is_public) VALUES
('/admin/roles/', 'GET', 'Admin - Role Management', FALSE),
('/admin/roles', 'GET', 'Admin - Role Management', FALSE),
('/admin/roles', 'POST', 'Admin - Role Management', FALSE),
('/admin/roles/{role_id}', 'GET', 'Admin - Role Management', FALSE),
('/admin/roles/{role_id}', 'PUT', 'Admin - Role Management', FALSE),
('/admin/roles/{role_id}', 'DELETE', 'Admin - Role Management', FALSE),
('/admin/roles/{role_id}/groups', 'PUT', 'Admin - Role Management', FALSE),
('/admin/roles/{role_id}/permissions', 'GET', 'Admin - Role Management', FALSE);

INSERT INTO Access_Point_Permission_Mapping (access_id, permission_id) VALUES

(18, 8),   -- VIEW_ROLE

(19, 8),   -- VIEW_ROLE

(20, 9),   -- ADD_ROLE

(21, 8),   -- VIEW_ROLE

(22, 10),  -- EDIT_ROLE

(23, 11),  -- DELETE_ROLE

(24, 10),  -- EDIT_ROLE

(25, 12);  -- VIEW_PERMISSION


INSERT INTO Access_Point (endpoint_path, method, module, is_public) VALUES
('/admin/permissions/', 'GET', 'Admin - Permission Management', FALSE),
('/admin/permissions', 'GET', 'Admin - Permission Management', FALSE),
('/admin/permissions', 'POST', 'Admin - Permission Management', FALSE),
('/admin/permissions/{permission_id}', 'GET', 'Admin - Permission Management', FALSE),
('/admin/permissions/{permission_id}', 'PUT', 'Admin - Permission Management', FALSE),
('/admin/permissions/{permission_id}', 'DELETE', 'Admin - Permission Management', FALSE),
('/admin/permissions/{permission_id}/group', 'PUT', 'Admin - Permission Management', FALSE);



-- Admin - Permission Management

INSERT INTO Access_Point_Permission_Mapping (access_id, permission_id) VALUES

(26, 12),  -- VIEW_PERMISSION

(27, 12),  -- VIEW_PERMISSION

(28, 13),  -- ADD_PERMISSION

(29, 12),  -- VIEW_PERMISSION

(30, 14),  -- EDIT_PERMISSION

(31, 15),  -- DELETE_PERMISSION

(32, 14);  -- EDIT_PERMISSION

INSERT INTO Access_Point (endpoint_path, method, module, is_public) VALUES
('/admin/groups/', 'GET', 'Admin - Permission Group Management', FALSE),
('/admin/groups', 'GET', 'Admin - Permission Group Management', FALSE),
('/admin/groups', 'POST', 'Admin - Permission Group Management', FALSE),
('/admin/groups/{group_id}', 'GET', 'Admin - Permission Group Management', FALSE),
('/admin/groups/{group_id}', 'PUT', 'Admin - Permission Group Management', FALSE),
('/admin/groups/{group_id}', 'DELETE', 'Admin - Permission Group Management', FALSE),
('/admin/groups/{group_id}/permissions', 'GET', 'Admin - Permission Group Management', FALSE);


-- Admin - Permission Group Management

INSERT INTO Access_Point_Permission_Mapping (access_id, permission_id) VALUES

(33, 16),  -- VIEW_GROUP

(34, 16),  -- VIEW_GROUP

(35, 17),  -- ADD_GROUP

(36, 16),  -- VIEW_GROUP

(37, 18),  -- EDIT_GROUP

(38, 19),  -- DELETE_GROUP

(39, 16);  -- VIEW_GROUP


-- Admin - User Management









 
--  show tables;
--  
 select * from access_point_permission_mapping;
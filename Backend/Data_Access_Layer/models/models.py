from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, Enum, Text
from sqlalchemy.orm import relationship
from ..utils.database import Base  # adjust import path based on your structure

# ----------------------- Role Table -----------------------
class Role(Base):
    __tablename__ = "Role"
    role_id = Column(Integer, primary_key=True, index=True)
    role_name = Column(String(100), nullable=False)

    users = relationship("User", secondary="User_Role", back_populates="roles")
    permission_groups = relationship("Permission_Group", secondary="Role_Permission_Group")

# ----------------------- User Table -----------------------
class User(Base):
    __tablename__ = "User"
    user_id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String(100))
    last_name = Column(String(100))
    mail = Column(String(150), unique=True)
    contact = Column(String(15))
    password = Column(String(255))
    is_active = Column(Boolean, default=True)

    roles = relationship("Role", secondary="User_Role", back_populates="users")

# ----------------------- User-Role Mapping -----------------------
class User_Role(Base):
    __tablename__ = "User_Role"
    user_id = Column(Integer, ForeignKey("User.user_id"), primary_key=True)
    role_id = Column(Integer, ForeignKey("Role.role_id"), primary_key=True)

# ----------------------- Permissions Table -----------------------
class Permissions(Base):
    __tablename__ = "Permissions"
    permission_id = Column(Integer, primary_key=True, index=True)
    permission_code = Column(String(100), unique=True, nullable=False)
    description = Column(Text)

    access_mappings = relationship("AccessPointPermission", back_populates="permission")
    permission_groups = relationship("Permission_Group", secondary="Permission_Group_Mapping")

# ----------------------- Permission Group -----------------------
class Permission_Group(Base):
    __tablename__ = "Permission_Group"
    group_id = Column(Integer, primary_key=True, index=True)
    group_name = Column(String(100), unique=True, nullable=False)

    permissions = relationship("Permissions", secondary="Permission_Group_Mapping")
    roles = relationship("Role", secondary="Role_Permission_Group")

# ----------------------- Permission Group Mapping -----------------------
class Permission_Group_Mapping(Base):
    __tablename__ = "Permission_Group_Mapping"
    permission_id = Column(Integer, ForeignKey("Permissions.permission_id"), primary_key=True)
    group_id = Column(Integer, ForeignKey("Permission_Group.group_id"), primary_key=True)

# ----------------------- AccessPoint Table -----------------------
class AccessPoint(Base):
    __tablename__ = "access_point"

    access_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    endpoint_path = Column(String(255), nullable=False)
    method = Column(Enum("GET", "POST", "PUT", "DELETE", name="http_method_enum"), nullable=False)
    module = Column(String(100), nullable=False)
    is_public = Column(Boolean, default=False)

    permission_mappings = relationship("AccessPointPermission", back_populates="access_point", cascade="all, delete-orphan")

# ----------------------- AccessPointPermission Mapping -----------------------
class AccessPointPermission(Base):
    __tablename__ = "access_point_permission_mapping"
    
    id = Column(Integer, primary_key=True, index=True)
    access_id = Column(Integer, ForeignKey("access_point.access_id"))
    permission_id = Column(Integer, ForeignKey("Permissions.permission_id"))  # Use ID instead of code
    
    access_point = relationship("AccessPoint", back_populates="permission_mappings")
    permission = relationship("Permissions", back_populates="access_mappings")

# ----------------------- Role-Permission Group Mapping -----------------------
class Role_Permission_Group(Base):
    __tablename__ = "Role_Permission_Group"
    role_id = Column(Integer, ForeignKey("Role.role_id"), primary_key=True)
    group_id = Column(Integer, ForeignKey("Permission_Group.group_id"), primary_key=True)

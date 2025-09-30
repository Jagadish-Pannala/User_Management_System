from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, Enum, Text, DateTime, func, JSON
from sqlalchemy.orm import relationship
from ..utils.database import Base  # adjust import path


# ----------------------- User Table -----------------------
class User(Base):
    __tablename__ = "User"

    user_id = Column(Integer, primary_key=True, index=True)
    user_uuid = Column(String(36), unique=True, nullable=False)
    first_name = Column(String(100))
    last_name = Column(String(100))
    mail = Column(String(150), unique=True)
    contact = Column(String(15))
    password = Column(String(255))
    is_active = Column(Boolean, default=True)
    password_last_updated = Column(DateTime, default=None)
    last_login_at = Column(DateTime, default=None)
    last_login_ip = Column(String(45), default=None)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    # explicitly define foreign_keys for ambiguous relationships
    roles = relationship(
        "Role",
        secondary="User_Role",
        back_populates="users",
        secondaryjoin="Role.role_id==User_Role.role_id",
        primaryjoin="User.user_id==User_Role.user_id",
    )
    assigned_roles = relationship(
        "User_Role",
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="User_Role.user_id"
    )
    assigned_permissions = relationship("AccessPointPermission", back_populates="assigned_by_user")
    created_permission_groups = relationship("Permission_Group", back_populates="created_by_user")
    created_access_points = relationship("AccessPoint", back_populates="created_by_user")
    audit_trails = relationship("AuditTrail", back_populates="user")


# ----------------------- Role Table -----------------------
class Role(Base):
    __tablename__ = "Role"

    role_id = Column(Integer, primary_key=True, index=True)
    role_uuid = Column(String(36), unique=True, nullable=False)
    role_name = Column(String(100), nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    users = relationship(
        "User",
        secondary="User_Role",
        back_populates="roles",
        primaryjoin="Role.role_id==User_Role.role_id",
        secondaryjoin="User.user_id==User_Role.user_id",
        foreign_keys="[User_Role.user_id, User_Role.role_id]"
    )
    permission_groups = relationship(
        "Permission_Group",
        secondary="Role_Permission_Group",
        back_populates="roles",
        cascade="all"
    )


# ----------------------- User_Role Mapping -----------------------
class User_Role(Base):
    __tablename__ = "User_Role"

    user_id = Column(Integer, ForeignKey("User.user_id", ondelete="RESTRICT"), primary_key=True)
    role_id = Column(Integer, ForeignKey("Role.role_id", ondelete="RESTRICT"), primary_key=True)
    assigned_by = Column(Integer, ForeignKey("User.user_id", ondelete="SET NULL"), nullable=True)
    assigned_at = Column(DateTime, server_default=func.now())

    user = relationship("User", back_populates="assigned_roles", foreign_keys=[user_id])
    role = relationship("Role")


# ----------------------- Permissions Table -----------------------
class Permissions(Base):
    __tablename__ = "Permissions"

    permission_id = Column(Integer, primary_key=True, index=True)
    permission_uuid = Column(String(36), unique=True, nullable=False)
    permission_code = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    access_mappings = relationship("AccessPointPermission", back_populates="permission", cascade="all, delete-orphan")
    permission_groups = relationship("Permission_Group", secondary="Permission_Group_Mapping", back_populates="permissions")


# ----------------------- Permission_Group Table -----------------------
class Permission_Group(Base):
    __tablename__ = "Permission_Group"

    group_id = Column(Integer, primary_key=True, index=True)
    group_uuid = Column(String(36), unique=True, nullable=False)
    group_name = Column(String(100), unique=True, nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    created_by = Column(Integer, ForeignKey("User.user_id", ondelete="SET NULL"), nullable=True)

    created_by_user = relationship("User", back_populates="created_permission_groups")
    permissions = relationship("Permissions", secondary="Permission_Group_Mapping", back_populates="permission_groups")
    roles = relationship("Role", secondary="Role_Permission_Group", back_populates="permission_groups")


# ----------------------- Permission_Group_Mapping -----------------------
class Permission_Group_Mapping(Base):
    __tablename__ = "Permission_Group_Mapping"

    permission_id = Column(Integer, ForeignKey("Permissions.permission_id", ondelete="RESTRICT"), primary_key=True)
    group_id = Column(Integer, ForeignKey("Permission_Group.group_id", ondelete="RESTRICT"), primary_key=True)
    assigned_by = Column(Integer, ForeignKey("User.user_id", ondelete="SET NULL"), nullable=True)
    assigned_at = Column(DateTime, server_default=func.now())


# ----------------------- AccessPoint Table -----------------------
class AccessPoint(Base):
    __tablename__ = "Access_Point"

    access_id = Column(Integer, primary_key=True, index=True)
    access_uuid = Column(String(36), unique=True, nullable=False)
    endpoint_path = Column(String(255), nullable=False)
    regex_pattern = Column(String(255), nullable=True)
    method = Column(Enum("GET", "POST", "PUT", "DELETE", name="http_method_enum"), nullable=False)
    module = Column(String(100), nullable=False)
    is_public = Column(Boolean, default=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    created_by = Column(Integer, ForeignKey("User.user_id", ondelete="SET NULL"), nullable=True)

    created_by_user = relationship("User", back_populates="created_access_points")
    permission_mappings = relationship("AccessPointPermission", back_populates="access_point", cascade="all, delete-orphan")


# ----------------------- AccessPointPermission Mapping -----------------------
class AccessPointPermission(Base):
    __tablename__ = "Access_Point_Permission_Mapping"

    id = Column(Integer, primary_key=True, index=True)
    access_id = Column(Integer, ForeignKey("Access_Point.access_id", ondelete="RESTRICT"))
    permission_id = Column(Integer, ForeignKey("Permissions.permission_id", ondelete="RESTRICT"))
    assigned_by = Column(Integer, ForeignKey("User.user_id", ondelete="SET NULL"), nullable=True)
    assigned_at = Column(DateTime, server_default=func.now())

    access_point = relationship("AccessPoint", back_populates="permission_mappings")
    permission = relationship("Permissions", back_populates="access_mappings")
    assigned_by_user = relationship("User", back_populates="assigned_permissions")


# ----------------------- Role-Permission Group Mapping -----------------------
class Role_Permission_Group(Base):
    __tablename__ = "Role_Permission_Group"

    role_id = Column(Integer, ForeignKey("Role.role_id", ondelete="RESTRICT"), primary_key=True)
    group_id = Column(Integer, ForeignKey("Permission_Group.group_id", ondelete="RESTRICT"), primary_key=True)
    assigned_by = Column(Integer, ForeignKey("User.user_id", ondelete="SET NULL"), nullable=True)
    assigned_at = Column(DateTime, server_default=func.now())


# ----------------------- AuditTrail Table -----------------------
class AuditTrail(Base):
    __tablename__ = "Audit_Trail"

    audit_id = Column(Integer, primary_key=True, index=True)
    audit_uuid = Column(String(36), unique=True, nullable=False)
    user_id = Column(Integer, ForeignKey("User.user_id", ondelete="SET NULL"), nullable=True)
    action_type = Column(Enum('CREATE','UPDATE','DELETE','LOGIN','LOGOUT','ASSIGN_ROLE','ASSIGN_PERMISSION','OTHER', name="action_type_enum"), nullable=False)
    entity_type = Column(String(100), nullable=False)
    entity_id = Column(Integer, nullable=True)
    old_data = Column(JSON, nullable=True)
    new_data = Column(JSON, nullable=True)
    ip_address = Column(String(45), nullable=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

    user = relationship("User", back_populates="audit_trails")

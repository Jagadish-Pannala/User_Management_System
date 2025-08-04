from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from ..models import models
from typing import Optional
from ..models.otp import OTP
from datetime import datetime


class AuthDAO:
    """Data Access Object for Authentication operations"""

    def __init__(self, db: Session):
        self.db = db

    # --------------------------
    # USER OPERATIONS
    # --------------------------

    def get_user_by_email(self, email: str) -> Optional[models.User]:
        return self.db.query(models.User).filter_by(mail=email).first()

    def get_active_user_by_email(self, email: str) -> Optional[models.User]:
        return self.db.query(models.User).filter(
            models.User.mail == email,
            models.User.is_active == True
        ).first()

    def create_user(self, user_data, hashed_password: str) -> models.User:
        new_user = models.User(
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            mail=user_data.mail,
            contact=user_data.contact,
            password=hashed_password
        )
        self.db.add(new_user)
        self.db.commit()
        self.db.refresh(new_user)
        return new_user

    def update_user_password(self, user: models.User, new_hashed_password: str) -> bool:
        try:
            user.password = new_hashed_password
            user.is_active = True
            self.db.commit()
            return True
        except SQLAlchemyError:
            self.db.rollback()
            return False

    def update_user_password_by_mail(self, user_mail: str, new_hashed_password: str) -> bool:
        user = self.db.query(models.User).filter(models.User.mail == user_mail).first()
        if user:
            return self.update_user_password(user, new_hashed_password)
        return False

    # --------------------------
    # ROLE OPERATIONS
    # --------------------------

    def get_general_role(self) -> Optional[models.Role]:
        return self.db.query(models.Role).filter_by(role_name="General").first()

    def assign_user_role(self, user_id: int, role_id: int):
        mapping = models.User_Role(user_id=user_id, role_id=role_id)
        self.db.add(mapping)
        self.db.commit()

    def get_user_roles(self, user_id: int) -> list[str]:
        result = self.db.query(models.Role.role_name).join(models.User_Role).filter(
            models.User_Role.user_id == user_id
        ).all()
        return [r[0] for r in result]

    # --------------------------
    # PERMISSION OPERATIONS
    # --------------------------

    def get_permission_group_ids_for_user(self, user_id: int) -> list[int]:
        result = self.db.query(models.Role_Permission_Group.group_id).join(
            models.User_Role, models.User_Role.role_id == models.Role_Permission_Group.role_id
        ).filter(models.User_Role.user_id == user_id).distinct().all()
        return [g[0] for g in result]

    def get_permissions_by_group_ids(self, group_ids: list[int]) -> list[str]:
        if not group_ids:
            return []

        result = self.db.query(models.Permissions.permission_code).join(
            models.Permission_Group_Mapping,
            models.Permissions.permission_id == models.Permission_Group_Mapping.permission_id
        ).filter(models.Permission_Group_Mapping.group_id.in_(group_ids)).distinct().all()

        return [p[0] for p in result]

    def get_access_point(self, path: str, method: str) -> Optional[models.AccessPoint]:
        return self.db.query(models.AccessPoint).filter_by(endpoint_path=path, method=method).first()

    def get_permission_codes_for_access_point(self, access_id: int) -> list[str]:
        result = self.db.query(models.Permissions.permission_code).join(
            models.AccessPointPermission,
            models.Permissions.permission_code == models.AccessPointPermission.permission_code
        ).filter(models.AccessPointPermission.access_id == access_id).all()
        return [p[0] for p in result]

    def get_user_permissions(self, user_id: int) -> list[str]:
        group_ids = self.get_permission_group_ids_for_user(user_id)
        return self.get_permissions_by_group_ids(group_ids)

    def get_valid_otp(self, email: str, otp: str) -> Optional[OTP]:
        return self.db.query(OTP).filter(
            OTP.email == email,
            OTP.otp == otp,
            OTP.expires_at > datetime.utcnow()
        ).first()

    def delete_otp(self, otp_record: OTP):
        self.db.delete(otp_record)
        self.db.commit()

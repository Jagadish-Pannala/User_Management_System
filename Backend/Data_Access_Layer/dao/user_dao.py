from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import or_, not_
from ..models import models
from typing import Optional, List
 
 
class UserDAO:
    """Data Access Object for User Profile operations"""
 
    def __init__(self, db: Session):
        self.db = db
 
    # --------------------------
    # USER OPERATIONS
    # --------------------------
 
    def get_user_by_email(self, email: str) -> Optional[models.User]:
        return self.db.query(models.User).filter_by(mail=email).first()
 
    def get_user_by_id(self, user_id: int) -> Optional[models.User]:
        return self.db.query(models.User).filter_by(user_id=user_id).first()
 
 
    def update_user(self, user: models.User, data: dict) -> bool:
        try:
            for field, value in data.items():
                setattr(user, field, value)
            self.db.commit()
            self.db.refresh(user)
            return True
        except SQLAlchemyError:
            self.db.rollback()
            return False
 
    def update_user_profile(self, user, update_data: dict) -> bool:
        try:
            for key, value in update_data.items():
                if hasattr(user, key):
                    setattr(user, key, value)
            self.db.commit()
            self.db.refresh(user)
            return True
        except Exception as e:
            self.db.rollback()
            print("Error updating user profile:", e)
            return False
 
    def deactivate_user(self, user: models.User) -> None:
        try:
            user.is_active = False
            self.db.commit()
        except SQLAlchemyError:
            self.db.rollback()
            raise
 
    # --------------------------
    # USER SEARCH
    # --------------------------
 
   
    def search_public_users(self, query: str, excluded_user_ids_subq):
        return self.db.query(models.User).filter(
            not_(models.User.user_id.in_(excluded_user_ids_subq)),
            or_(
                models.User.first_name.ilike(f"%{query}%"),
                models.User.last_name.ilike(f"%{query}%"),
                models.User.mail.ilike(f"%{query}%"),
                models.User.contact.ilike(f"%{query}%")
            )
        ).all()
 
    def search_all_users(self, query: str) -> List[models.User]:
        return self.db.query(models.User).filter(
            or_(
                models.User.first_name.ilike(f"%{query}%"),
                models.User.last_name.ilike(f"%{query}%"),
                models.User.mail.ilike(f"%{query}%"),
                models.User.contact.ilike(f"%{query}%")
            )
        ).all()
 
    def search_non_admin_users(self, query: str, admin_ids: List[int]) -> List[models.User]:
        return self.db.query(models.User).filter(
            not_(models.User.user_id.in_(admin_ids)),
            or_(
                models.User.first_name.ilike(f"%{query}%"),
                models.User.last_name.ilike(f"%{query}%"),
                models.User.mail.ilike(f"%{query}%"),
                models.User.contact.ilike(f"%{query}%")
            )
        ).all()
 
    def search_all_suggestions(self, query: str) -> List[models.User]:
        return self.db.query(models.User).filter(
            or_(
                models.User.first_name.ilike(f"%{query}%"),
                models.User.last_name.ilike(f"%{query}%"),
                models.User.mail.ilike(f"%{query}%")
            )
        ).limit(10).all()
 
    def search_suggestions_exclude_admins(self, query: str, admin_ids: List[int]) -> List[models.User]:
        return self.db.query(models.User).filter(
            not_(models.User.user_id.in_(admin_ids)),
            or_(
                models.User.first_name.ilike(f"%{query}%"),
                models.User.last_name.ilike(f"%{query}%"),
                models.User.mail.ilike(f"%{query}%")
            )
        ).limit(10).all()
   
    def search_all_users(self, query: str):
        return self.db.query(models.User).filter(
            or_(
                models.User.first_name.ilike(f"%{query}%"),
                models.User.last_name.ilike(f"%{query}%"),
                models.User.mail.ilike(f"%{query}%"),
                models.User.contact.ilike(f"%{query}%")
            )
        ).all()
 
    # --------------------------
    # ADMIN/ROLE HELPERS
    # --------------------------
 
    def get_admin_user_ids(self) -> List[int]:
        admin_ids = self.db.query(models.User_Role.user_id)\
            .join(models.Role)\
            .filter(models.Role.role_name.in_(["Admin", "Super Admin"]))\
            .distinct().all()
        return [uid[0] for uid in admin_ids]
 
    def get_non_admin_user_ids(self):
        return self.db.query(models.User_Role.user_id)\
            .join(models.Role)\
            .filter(models.Role.role_name.in_(["Admin", "Super Admin"]))\
            .subquery()
 
    def get_user_roles(self, user_id: int) -> List[str]:
        roles = self.db.query(models.Role.role_name)\
            .join(models.User_Role)\
            .filter(models.User_Role.user_id == user_id).all()
        return [role[0] for role in roles]
 
    def get_user_permissions(self, user_id: int) -> List[str]:
        permissions = self.db.query(models.Permission.permission_name)\
            .join(models.Role_Permission, models.Permission.permission_id == models.Role_Permission.permission_id)\
            .join(models.Role, models.Role_Permission.role_id == models.Role.role_id)\
            .join(models.User_Role, models.User_Role.role_id == models.Role.role_id)\
            .filter(models.User_Role.user_id == user_id)\
            .distinct().all()
        return [p[0] for p in permissions]
 
    def clear_roles(self, user_id: int) -> None:
        try:
            self.db.query(models.User_Role).filter_by(user_id=user_id).delete()
            self.db.commit()
        except SQLAlchemyError:
            self.db.rollback()
            raise
 
    def assign_role(self, user_id: int, role_id: int) -> None:
        try:
            new_assignment = models.User_Role(user_id=user_id, role_id=role_id)
            self.db.add(new_assignment)
            self.db.commit()
        except SQLAlchemyError:
            self.db.rollback()
            raise
 
    def get_all_users(self) -> List[models.User]:
        return self.db.query(models.User).all()
 
    def get_users_with_roles(self) -> List[dict]:
        results = (
            self.db.query(
                models.User.user_id,
                models.User.first_name,
                models.User.last_name,
                models.User.mail,
                models.Role.role_name
            )
            .join(models.User_Role, models.User.user_id == models.User_Role.user_id)
            .join(models.Role, models.User_Role.role_id == models.Role.role_id)
            .all()
        )
 
        user_map = {}
        for user_id, first_name, last_name, mail, role_name in results:
            if user_id not in user_map:
                user_map[user_id] = {
                    "user_id": user_id,
                    "first_name": first_name,
                    "last_name": last_name,
                    "mail": mail,
                    "roles": []
                }
            user_map[user_id]["roles"].append(role_name)
 
        return list(user_map.values())
   
    def get_role_by_name(self, role_name: str) -> models.Role:
        return self.db.query(models.Role).filter(models.Role.role_name == role_name).first()
 
    def create_user(self, user: models.User) -> models.User:
        try:
            self.db.add(user)
            self.db.commit()
            self.db.refresh(user)
            return user
        except SQLAlchemyError:
            self.db.rollback()
            raise
 
    def map_user_role(self, user_id: int, role_id: int):
        try:
            self.db.execute(
                models.User_Role.__table__.insert().values(user_id=user_id, role_id=role_id)
            )
            self.db.commit()
        except SQLAlchemyError:
            self.db.rollback()
            raise
 
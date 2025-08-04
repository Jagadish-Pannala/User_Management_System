from sqlalchemy.orm import Session
from ...Data_Access_Layer.dao.user_dao import UserDAO
from ...Data_Access_Layer.models import models
from ...Data_Access_Layer.utils.database import SessionLocal
from ..utils.password_utils import hash_password
 
 
class UserService:
    def __init__(self, db: Session):
        self.db = db
        self.dao = UserDAO(self.db)
 
    def list_users(self):
        return self.dao.get_all_users()
 
    def get_users_with_roles(self):
        users = self.dao.get_users_with_roles()
        result = []
        for user in users:
            full_name = f"{user['first_name']} {user['last_name']}"
            role_names = [role for role in user['roles']]
            result.append({
                "user_id": user['user_id'],
                "name": full_name,
                "roles": role_names
            })
        return result
 
    def get_user(self, user_id):
        return self.dao.get_user_by_id(user_id)
 
    def create_user(self, user_schema):
        existing = self.dao.get_user_by_email(user_schema.mail)
        if existing:
            raise ValueError("User already exists")
 
        hashed_password = hash_password(user_schema.password)
        new_user = models.User(
            first_name=user_schema.first_name,
            last_name=user_schema.last_name,
            mail=user_schema.mail,
            contact=user_schema.contact,
            password=hashed_password,
            is_active=user_schema.is_active
        )
 
        # Step 1: Create user
        created_user = self.dao.create_user(new_user)
 
        # Step 2: Get General role
        general_role = self.dao.get_role_by_name("General")
        if not general_role:
            raise ValueError("Role 'General' not found")
 
        # Step 3: Map user to role
        self.dao.map_user_role(created_user.user_id, general_role.role_id)
 
        return created_user
 
 
 
    def update_user(self, user_id, user_schema):
        user = self.dao.get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")
 
        updated_data = {
            "first_name": user_schema.first_name,
            "last_name": user_schema.last_name,
            "mail": user_schema.mail,
            "contact": user_schema.contact,
            "is_active": user_schema.is_active,
            "password": hash_password(user_schema.password)
        }
 
        success = self.dao.update_user(user, updated_data)
 
        if success:
            return self.dao.get_user_by_id(user_id)
        else:
            raise RuntimeError("User update failed")
 
    def deactivate_user(self, user_id):
        user = self.dao.get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        self.dao.deactivate_user(user)
 
    def update_user_roles(self, user_id, role_ids):
        user = self.dao.get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")
 
        if not user.is_active:
            raise ValueError("Cannot update roles for inactive user")
 
        self.dao.clear_roles(user_id)
 
        if not role_ids:
            general_role = self.db.query(models.Role).filter_by(role_name="General").first()
            if not general_role:
                raise RuntimeError("'General' role not found")
            self.dao.assign_role(user_id, general_role.role_id)
            return "No roles provided. Assigned 'General' role."
 
        for role_id in role_ids:
            self.dao.assign_role(user_id, role_id)
 
        return "Roles updated successfully"
 
    def get_user_roles(self, user_id):
        return [r[0] for r in self.dao.get_user_roles(user_id)]
 
    def update_user_profile(self, user_id, profile_data):
        user = self.dao.get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")
 
        update_fields = {
            "first_name": profile_data.first_name,
            "last_name": profile_data.last_name,
            "contact": profile_data.contact,
        }
 
        return self.dao.update_user_profile(user_id, update_fields)
 
    def search_public_users(self, search_term: str):
        return self.dao.search_public_users(search_term)
 
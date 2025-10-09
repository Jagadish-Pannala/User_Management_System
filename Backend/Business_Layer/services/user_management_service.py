from sqlalchemy.orm import Session
from ...Data_Access_Layer.dao.user_dao import UserDAO
from ...Data_Access_Layer.models import models
from ...Data_Access_Layer.utils.database import SessionLocal
from ..utils.password_utils import hash_password, verify_password, check_password_match
from ..utils.email_utils import send_welcome_email
from ..utils.input_validators import validate_email_format, validate_password_strength, validate_name, validate_contact_number
from ..utils.generate_uuid7 import generate_uuid7
# Import the audit decorator
from ..utils.audit_decorator import audit_action_with_request


from ...Api_Layer.interfaces.user_management import UserBaseIn
import pandas as pd
 
 
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
                "user_uuid": user['user_uuid'],
                "name": full_name,
                "roles": role_names,
                "mail": user['mail']
            })
        return result
    
    def get_users_with_roles_id(self):
        users = self.dao.get_users_with_roles()
        result = []
        for user in users:
            full_name = f"{user['first_name']} {user['last_name']}"
            role_names = [role for role in user['roles']]
            result.append({
                "user_id": user['user_id'],
                "name": full_name,
                "roles": role_names,
                "mail": user['mail']
            })
        return result

    def get_user_uuid(self, user_uuid):
        return self.dao.get_user_by_uuid(user_uuid)
    
    def get_user(self, user_id):
        return self.dao.get_user_by_id(user_id)

    @audit_action_with_request(
        action_type='CREATE',
        entity_type='User',
        get_entity_id=lambda *args, **kwargs: None,  # Will be extracted from result
        capture_new_data=True,
        description="Created new user: {mail}"
    )
    def create_user(self, user_schema, created_by_user_id: int, **kwargs):
        existing = self.dao.get_user_by_email(user_schema.mail)
        if existing:
            raise ValueError("User already exists")
        validate_email_format(user_schema.mail)
        validate_name(user_schema.first_name)
        validate_name(user_schema.last_name)
        validate_contact_number(user_schema.contact)
        validate_password_strength(user_schema.password)
        
        hashed_password = hash_password(user_schema.password)
        new_user = models.User(
            user_uuid=generate_uuid7(),
            first_name=user_schema.first_name,
            last_name=user_schema.last_name,
            mail=user_schema.mail,
            contact=user_schema.contact,
            password=hashed_password,
            is_active=user_schema.is_active
        )
        send_welcome_email(user_schema.mail, user_schema.first_name, user_schema.password)

        # Step 1: Create user
        created_user = self.dao.create_user(new_user)

        # Step 2: Get General role
        general_role = self.dao.get_role_by_name("General")
        if not general_role:
            raise ValueError("Role 'General' not found")

        # Step 3: Map user to role
        self.dao.map_user_role(created_user.user_id, general_role.role_id, created_by_user_id)

        return created_user


    
    def bulk_create_users(self, df: pd.DataFrame, created_by_user_id: int):
        def generate_password(first_name, contact):
            contact_str = str(contact)  # ensure it’s a string
            return f"{first_name[:4]}@{contact_str[-4:]}"

        created_users = []
        failed_rows = []

        # Optional: fetch "General" role once, not for each user
        general_role = self.dao.get_role_by_name("General")
        if not general_role:
            raise ValueError("Role 'General' not found")

        for index, row in df.iterrows():
            try:
                # Build schema manually
                user_schema = UserBaseIn(
                    first_name=row["first_name"],
                    last_name=row["last_name"],
                    mail=row["mail"],
                    contact=str(row["contact"]),
                    password=generate_password(row["first_name"], row["contact"]),  # default if not given
                    is_active=True
                )

                # Reuse same validation logic
                existing = self.dao.get_user_by_email(user_schema.mail)
                if existing:
                    raise ValueError(f"User with email {user_schema.mail} already exists")

                validate_email_format(user_schema.mail)
                validate_name(user_schema.first_name)
                validate_name(user_schema.last_name)
                validate_contact_number(user_schema.contact)
                validate_password_strength(user_schema.password)

                hashed_password = hash_password(user_schema.password)

                new_user = models.User(
                    user_uuid=generate_uuid7(),
                    first_name=user_schema.first_name,
                    last_name=user_schema.last_name,
                    mail=user_schema.mail,
                    contact=user_schema.contact,
                    password=hashed_password,
                    is_active=True
                )

                # Step 1: Create user
                created_user = self.dao.create_user(new_user)

                # Step 2: Map default role
                self.dao.map_user_role(created_user.user_id, general_role.role_id, created_by_user_id)

                # Step 3: Send welcome mail
                send_welcome_email(user_schema.mail, user_schema.first_name, user_schema.password)

                created_users.append(created_user)

            except Exception as e:
                failed_rows.append({
                    "row_number": index + 2,  # Excel rows start at 2
                    "mail": row.get("mail"),
                    "error": str(e)
                })

        return {
            "created_count": len(created_users),
            "failed_count": len(failed_rows),
            "failed_rows": failed_rows
        }
    

 
    @audit_action_with_request(
        action_type='UPDATE',
        entity_type='User',
        get_entity_id=lambda self, user_uuid, *args, **kwargs: self.dao.get_user_by_uuid(user_uuid).user_id if self.dao.get_user_by_uuid(user_uuid) else None,
        capture_old_data=True,
        capture_new_data=True
    )
    def update_user_uuid(self, user_uuid, user_schema, **kwargs):
        user = self.dao.get_user_by_uuid(user_uuid)
        if not user:
            raise ValueError("User not found")
        # Validations
        validate_email_format(user_schema.mail)
        validate_name(user_schema.first_name)
        validate_name(user_schema.last_name)
        validate_contact_number(user_schema.contact)
        if user.mail != user_schema.mail:
            existing = self.dao.get_user_by_email(user_schema.mail)
            if existing:
                raise ValueError("User already exists")
        updated_data = {
            "first_name": user_schema.first_name,
            "last_name": user_schema.last_name,
            "mail": user_schema.mail,
            "contact": user_schema.contact,
            "is_active": user_schema.is_active,
        }
        password_changed = False
        # Password update handling (SAFE)
        if user_schema.password and user_schema.password.strip() != "":
            # Assume anything provided is a NEW plain password (frontend never sends old hash)
            # Validate and hash it
            validate_password_strength(user_schema.password)
            updated_data["password"] = hash_password(user_schema.password)
            password_changed = True
        else:
            # Keep existing hashed password as-is
            updated_data["password"] = user.password
        success = self.dao.update_user(user, updated_data)
        if success:
            if password_changed:
                self.dao.password_last_updated(user.user_id)
            return self.dao.get_user_by_id(user.user_id)
        else:
            raise RuntimeError("User update failed")

    @audit_action_with_request(
        action_type='UPDATE',
        entity_type='User',
        get_entity_id=lambda self, user_id, *args, **kwargs: user_id,
        capture_old_data=True,
        capture_new_data=True
    )
    def update_user(self, user_id, user_schema, **kwargs):
        user = self.dao.get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        # Validations
        validate_email_format(user_schema.mail)
        validate_name(user_schema.first_name)
        validate_name(user_schema.last_name)
        validate_contact_number(user_schema.contact)
        if user.mail != user_schema.mail:
            existing = self.dao.get_user_by_email(user_schema.mail)
            if existing:
                raise ValueError("User already exists")
        updated_data = {
            "first_name": user_schema.first_name,
            "last_name": user_schema.last_name,
            "mail": user_schema.mail,
            "contact": user_schema.contact,
            "is_active": user_schema.is_active,
        }
        password_changed = False
        # Password update handling (SAFE)
        if user_schema.password and user_schema.password.strip() != "":
            # Assume anything provided is a NEW plain password (frontend never sends old hash)
            # Validate and hash it
            validate_password_strength(user_schema.password)
            updated_data["password"] = hash_password(user_schema.password)
            password_changed = True
        else:
            # Keep existing hashed password as-is
            updated_data["password"] = user.password
        success = self.dao.update_user(user, updated_data)
        if success:
            if password_changed:
                self.dao.password_last_updated(user_id)
            return self.dao.get_user_by_id(user_id)
        else:
            raise RuntimeError("User update failed")

    @audit_action_with_request(
        action_type='DELETE',
        entity_type='User',
        get_entity_id=lambda self, user_id, *args, **kwargs: user_id,
        capture_old_data=True,
        description="Deactivated user account"
    )
    def deactivate_user(self, user_id, **kwargs):
        user = self.dao.get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        self.dao.deactivate_user(user)

    @audit_action_with_request(
        action_type='DELETE',
        entity_type='User',
        get_entity_id=lambda self, user_uuid, *args, **kwargs: self.dao.get_user_by_uuid(user_uuid).user_id if self.dao.get_user_by_uuid(user_uuid) else None,
        capture_old_data=True,
        description="Deactivated user account"
    )
    def deactivate_user_uuid(self, user_uuid, **kwargs):
        user = self.dao.get_user_by_uuid(user_uuid)
        if not user:
            raise ValueError("User not found")
        self.dao.deactivate_user(user)
        
    
    @audit_action_with_request(
    action_type='ASSIGN_ROLE',
    entity_type='User_Role',
    get_entity_id=lambda self, user_uuid, *args, **kwargs: (
        self.dao.get_user_by_uuid(user_uuid).user_id
        if self.dao.get_user_by_uuid(user_uuid) else None
    ),
    capture_old_data=False,
    capture_new_data=False,
    description="Updated user roles"
    )
    def update_user_roles_uuid(self, user_uuid, role_uuids, updated_by_user_id: int, audit_data=None, **kwargs):
        if audit_data is None:
            audit_data = {}
        
        # Fetch the user
        user = self.dao.get_user_by_uuid(user_uuid)
        if not user:
            raise ValueError("User not found")
        
        if not user.is_active:
            raise ValueError("Cannot update roles for inactive user")
        
        # ----- Capture old roles (for audit display) -----
        old_roles = self.get_user_roles(user.user_id)  # Role names/details for audit
        audit_data['old_data'] = {"roles": old_roles}
        
        # ----- Get current role UUIDs -----
        current_roles_uuids = self.get_user_roles_by_uuid(user.user_id)
        current_role_set = set(current_roles_uuids)
        
        # ----- Handle empty role_uuids (assign General role) -----
        if not role_uuids:
            general_role = self.db.query(models.Role).filter_by(role_name="General").first()
            if not general_role:
                raise RuntimeError("'General' role not found")
            role_uuids = [general_role.role_uuid]
        
        # ----- Validate and deduplicate incoming role_uuids -----
        # Remove duplicates from input and convert to set
        new_role_set = set(role_uuids)
        
        # ----- Calculate differences using set operations -----
        roles_to_add = new_role_set - current_role_set      # New roles to assign
        roles_to_remove = current_role_set - new_role_set   # Roles to remove
        
        # ----- Remove roles that are no longer needed -----
        if roles_to_remove:
            for role_uuid in roles_to_remove:
                self.dao.remove_role_by_uuid(user.user_id, role_uuid)
        
        # ----- Add only new roles (preserves existing roles' assigned_by) -----
        if roles_to_add:
            for role_uuid in roles_to_add:
                # Double-check role doesn't exist before inserting (safety check)
                existing = self.db.query(models.User_Role).join(models.Role).filter(
                    models.User_Role.user_id == user.user_id,
                    models.Role.role_uuid == role_uuid
                ).first()
                
                if not existing:
                    self.dao.assign_role_uuid(user.user_id, role_uuid, updated_by_user_id)
        
        # ----- Capture new roles for audit -----
        # Only query if there were actual changes
        if roles_to_add or roles_to_remove:
            new_roles = self.get_user_roles(user.user_id)
        else:
            new_roles = old_roles  # No changes, reuse old data
        
        audit_data['new_data'] = {"roles": new_roles}
        
        # ----- Return meaningful message -----
        if not roles_to_add and not roles_to_remove:
            return "No role changes needed"
        
        changes = []
        if roles_to_add:
            changes.append(f"{len(roles_to_add)} role(s) added")
        if roles_to_remove:
            changes.append(f"{len(roles_to_remove)} role(s) removed")
        
        return "Roles updated successfully"

    
    @audit_action_with_request(
        action_type='ASSIGN_ROLE',
        entity_type='User',
        get_entity_id=lambda self, user_id, *args, **kwargs: user_id,
        capture_old_data=True,
        capture_new_data=True,
        description="Updated user roles"
    )
    def update_user_roles(self, user_id, role_ids, updated_by_user_id: int, **kwargs):
        user = self.dao.get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")

        if not user.is_active:
            raise ValueError("Cannot update roles for inactive user")

        self.dao.clear_roles(user.user_id)

        if not role_ids:
            general_role = self.db.query(models.Role).filter_by(role_name="General").first()
            if not general_role:
                raise RuntimeError("'General' role not found")
            self.dao.assign_role(user.user_id, general_role.role_id, updated_by_user_id)
            return "No roles provided. Assigned 'General' role."

        for role_id in role_ids:
            self.dao.assign_role(user.user_id, int(role_id), updated_by_user_id)

        return "Roles updated successfully"

    def get_user_roles(self, user_id):
        return [r for r in self.dao.get_user_roles(user_id)]
    
    def get_user_roles_by_uuid(self, user_id):
        return [r for r in self.dao.get_user_roles_by_uuid(user_id)]
    
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
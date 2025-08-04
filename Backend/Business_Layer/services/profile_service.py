from fastapi import HTTPException
from ..utils.password_utils import hash_password
from .base_service import BaseService
from ...Data_Access_Layer.dao.user_dao import UserDAO
from ...Api_Layer.interfaces.general_user import EditProfile, EditProfileHr


class ProfileService(BaseService):
    def __init__(self):
        super().__init__()
        self.dao = UserDAO(self.db)

    def get_profile(self, current_user: dict):
        user = self.dao.get_user_by_email(current_user["email"])
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        return {
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.mail,
            "contact": user.contact,
            "is_active": user.is_active,
            "can_edit": "EDIT_OWN_PROFILE" in current_user.get("permissions", [])
        }

    def update_profile(self, profile: EditProfile, current_user: dict):
        if "EDIT_OWN_PROFILE" not in current_user.get("permissions", []):
            raise HTTPException(status_code=403, detail="You don't have permission to edit your profile")

        user = self.dao.get_user_by_email(current_user["email"])
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        success = self.dao.update_user_profile(user, {
            "first_name": profile.first_name,
            "last_name": profile.last_name,
            "contact": profile.contact,
            "password": hash_password(profile.password)
        })

        if not success:
            raise HTTPException(status_code=500, detail="Failed to update profile")

        return {"message": "Profile updated successfully"}

    def search_users(self, query: str, current_user: dict):
        permissions = current_user.get("permissions", [])
        has_edit_permission = "EDIT_ANY_USER" in permissions

        if "VIEW_USER_ALL" in permissions:
            users = self.dao.search_all_users(query)
        elif "VIEW_USER_PUBLIC" in permissions:
            excluded_user_ids = self.dao.get_non_admin_user_ids()
            users = self.dao.search_public_users(query, excluded_user_ids)
        else:
            raise HTTPException(status_code=403, detail="You do not have permission to view users")

        return [
            {
                "user_id": u.user_id,
                "name": f"{u.first_name} {u.last_name}",
                "email": u.mail,
                "contact": u.contact,
                "is_active": u.is_active,
                "can_edit": True if "VIEW_USER_ALL" in permissions else has_edit_permission
            }
            for u in users
        ]

    def user_search_suggestions(self, query: str, current_user: dict):
        permissions = current_user.get("permissions", [])

        if "VIEW_USER_ALL" in permissions:
            users = self.dao.search_all_suggestions(query)
        elif "VIEW_USER_PUBLIC" in permissions:
            admin_ids = self.dao.get_admin_user_ids()
            users = self.dao.search_suggestions_exclude_admins(query, admin_ids)
        else:
            raise HTTPException(status_code=403, detail="You do not have permission to view suggestions")

        return [
            {
                "name": f"{u.first_name} {u.last_name}",
                "email": u.mail
            }
            for u in users
        ]

    def get_user_by_id(self, user_id: int, current_user: dict):
        user = self.dao.get_user_by_id(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        return {
            "user_id": user.user_id,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.mail,
            "contact": user.contact,
            "is_active": user.is_active
        }

    def update_user_by_id(self, user_id: int, profile: EditProfileHr, current_user: dict):
        user = self.dao.get_user_by_id(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        success = self.dao.update_user_profile(user, {
            "first_name": profile.first_name,
            "last_name": profile.last_name,
            "contact": profile.contact,
            "is_active": profile.is_active
        })

        if not success:
            raise HTTPException(status_code=500, detail="Failed to update user")

        return {"message": "User updated successfully"}

from fastapi import HTTPException
from sqlalchemy.orm import Session
from ...Data_Access_Layer.dao import role_dao
from ...Api_Layer.interfaces.role_mangement import RoleBase, RolePermissionGroupUpdate,RoleGroupRequest

class RoleService:
    def __init__(self, db: Session):
        self.db = db

    def list_roles(self):
        return role_dao.get_all_roles(self.db)

    def get_role_by_id(self, role_id: int):
        role = role_dao.get_role(self.db, role_id)
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")
        return role


    def _normalize_role_name(self, role_name: str) -> str:
        """
        Validate and normalize role name for duplicate checking:
        - Allow only letters (A–Z, a–z), spaces, and hyphens
        - No digits or other special characters allowed
        - Remove leading/trailing spaces
        - Replace multiple spaces with a single space
        - Lowercase for comparison
        """
        import re

        # 1. Validation — ensure only allowed characters
        if not re.fullmatch(r"[A-Za-z\s\-]+", role_name.strip()):
            raise HTTPException(
                status_code=400,
                detail="Role name can only contain letters, spaces, and hyphens"
            )

        # 2. Normalize spaces and lowercase for comparison
        cleaned = re.sub(r'\s+', ' ', role_name.strip())
        return cleaned.lower()


    def _check_duplicate_role(self, role_name: str, exclude_role_id: int = None):
        normalized_new = self._normalize_role_name(role_name)
        roles = role_dao.get_all_roles(self.db)  # returns list of role objects

        for role in roles:
            normalized_existing = self._normalize_role_name(role.role_name)
            if normalized_existing == normalized_new:
                if exclude_role_id is None or role.role_id != exclude_role_id:
                    raise HTTPException(
                        status_code=400,
                        detail="Role name already exists (case-insensitive, space-insensitive)"
                    )


    def create_role(self, role_data: RoleBase):
        self._check_duplicate_role(role_data.role_name)
        return role_dao.create_role(self.db, role_data)

    def update_role(self, role_id: int, role_data: RoleBase):
        self._check_duplicate_role(role_data.role_name, exclude_role_id=role_id)
        return role_dao.update_role(self.db, role_id, role_data)

    def delete_role(self, role_id: int):
        return role_dao.delete_role(self.db, role_id)
    

    def update_role_permission_groups(self, role_id: int, payload: RolePermissionGroupUpdate):
        return role_dao.update_role_groups(self.db, role_id, payload.group_ids)

    def get_permissions_by_role(self, role_id: int):
        return role_dao.get_permissions_by_role(self.db, role_id)
    
    def add_permission_groups_to_role(self, role_id: int, group_ids: list[int]):
        return role_dao.add_permission_groups_to_role(self.db, role_id, group_ids)

    def remove_permission_group_from_role(self, role_id: int, group_id: int):
        return role_dao.remove_permission_group_from_role(self.db, role_id, group_id)

    def update_permission_groups_for_role(self, role_id: int, group_ids: list[int]):
        return role_dao.update_permission_groups_for_role(self.db, role_id, group_ids)

    def get_permission_groups_by_role(self, role_id: int):
        return role_dao.get_permission_groups_by_role(self.db, role_id)
    
    def get_unassigned_permission_groups(self, role_id: int):
        return role_dao.get_unassigned_permission_groups(self.db, role_id)
    
    

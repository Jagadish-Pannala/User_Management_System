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

    def create_role(self, role_data: RoleBase):
        existing = role_dao.get_role_by_name(self.db, role_data.role_name)
        if existing:
            raise HTTPException(status_code=400, detail="Role name already exists")
        return role_dao.create_role(self.db, role_data)

    def update_role(self, role_id: int, role_data: RoleBase):
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

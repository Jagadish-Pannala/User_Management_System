from fastapi import HTTPException
from sqlalchemy.orm import Session
from ...Data_Access_Layer.dao.permission_dao import PermissionDAO
from ...Data_Access_Layer.dao.group_dao import PermissionGroupDAO
from ...Data_Access_Layer.dao.access_point_dao import AccessPointDAO

class PermissionService:
    def __init__(self, db: Session):
        self.db = db
        self.dao = PermissionDAO(db)
        self.group_dao = PermissionGroupDAO(db)
        self.access_point_dao = AccessPointDAO(db)

    def create_permission_minimal(self, permission_code: str, description: str, group_id: int = None):
        existing = self.dao.get_by_code(permission_code)
        if existing:
            raise HTTPException(status_code=400, detail=f"Permission code '{permission_code}' already exists")

        permission = self.dao.create(permission_code, description)

        if not group_id:
            default_group = self.group_dao.get_group_by_name("newly_created_permissions_group")
            if not default_group:
                raise HTTPException(status_code=500, detail="Default group not found")
            group_id = default_group.group_id
        else:
            group = self.group_dao.get_group_by_id(group_id)
            if not group:
                raise HTTPException(status_code=404, detail="Provided group not found")

        self.dao.map_to_group(permission.permission_id, group_id)

        return {
            "message": "Permission created and assigned to group successfully",
            "permission_id": permission.permission_id,
            "group_id": group_id
        }

    def list_permissions(self):
        return self.dao.get_all()

    def get_permission(self, permission_id: int):
        permission = self.dao.get_by_id(permission_id)
        if not permission:
            raise HTTPException(status_code=404, detail="Permission not found")
        return permission

    def update_permission(self, permission_id: int, code: str, desc: str):
        permission = self.dao.get_by_id(permission_id)
        if not permission:
            raise HTTPException(status_code=404, detail="Permission not found")

        if permission.permission_code != code and self.dao.get_by_code(code):
            raise HTTPException(status_code=400, detail=f"Permission code '{code}' already exists")

        return self.dao.update(permission, code, desc)


    def delete_permission(self, permission_id: int):
        permission = self.dao.get_by_id(permission_id)
        if not permission:
            raise HTTPException(status_code=404, detail="Permission not found")
        self.dao.delete(permission)

    def delete_permission_cascade(self, permission_id: int):
        if not self.dao.get_by_id(permission_id):
            raise HTTPException(status_code=404, detail="Permission not found")
        self.dao.delete_cascade(permission_id)

    def reassign_group(self, permission_id: int, group_id: int):
        if not self.dao.get_by_id(permission_id):
            raise HTTPException(status_code=404, detail="Permission not found")
        if not self.group_dao.get_group_by_id(group_id):
            raise HTTPException(status_code=404, detail="Group not found")
        self.dao.update_group_mapping(permission_id, group_id)

    def list_unmapped_permissions(self):
        return self.dao.get_unmapped()

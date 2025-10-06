import re
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from ...Data_Access_Layer.dao.permission_dao import PermissionDAO
from ...Data_Access_Layer.dao.group_dao import PermissionGroupDAO
from ...Data_Access_Layer.dao.access_point_dao import AccessPointDAO
from ..utils.generate_uuid7 import generate_uuid7

# Regex to allow only UPPERCASE letters separated by underscores
PERMISSION_CODE_PATTERN = re.compile(r'^[A-Z]+(_[A-Z]+)*$')

class PermissionService:
    def __init__(self, db: Session):
        self.db = db
        self.dao = PermissionDAO(db)
        self.group_dao = PermissionGroupDAO(db)
        self.access_point_dao = AccessPointDAO(db)

    def create_permission_minimal(self, permission_code: str, description: str, group_uuid: str = None):
        group_id = None
        # ✅ Validate empty or whitespace-only values
        if not permission_code or not permission_code.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Permission code cannot be empty"
            )
        if not description or not description.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Description cannot be empty"
            )

        # ✅ Validate format of permission_code
        permission_code = permission_code.strip()
        if not PERMISSION_CODE_PATTERN.fullmatch(permission_code):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "Invalid permission code format. Use only uppercase letters and underscores. "
                    "Example: VIEW_USER_PUBLIC"
                )
            )

        # ✅ Check if permission already exists
        existing = self.dao.get_by_code(permission_code)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Permission code '{permission_code}' already exists"
            )

        # ✅ Create permission
        permission = self.dao.create(permission_code, description.strip(),generate_uuid7())

        # ✅ Assign to group
        if not group_uuid:
            default_group = self.group_dao.get_group_by_name("newly_created_permissions_group")
            if not default_group:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Default group not found"
                )
            group_uuid = default_group.group_uuid
            group_id = default_group.group_id
        else:
            group = self.group_dao.get_group_by_uuid(group_uuid)
            if not group:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Provided group not found"
                )
            group_id = group.group_id
        self.dao.map_to_group(permission.permission_id, group_id)

        return {
            "message": "Permission created and assigned to group successfully",
            "permission_uuid": permission.permission_uuid,
            "group_uuid": group_uuid
        }

    def list_permissions(self):
        return self.dao.get_all()

    def get_permission(self, permission_uuid: str):
        permission = self.dao.get_by_uuid(permission_uuid)
        if not permission:
            raise HTTPException(status_code=404, detail="Permission not found")
        return permission

    def update_permission(self, permission_uuid: str, code: str, desc: str):
        permission = self.dao.get_by_uuid(permission_uuid)
        if not permission:
            raise HTTPException(status_code=404, detail="Permission not found")

        # ✅ Validate new code if it's changed
        if not code or not code.strip():
            raise HTTPException(status_code=400, detail="Permission code cannot be empty")
        if not desc or not desc.strip():
            raise HTTPException(status_code=400, detail="Description cannot be empty")

        code = code.strip()
        if not PERMISSION_CODE_PATTERN.fullmatch(code):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid permission code format. Use only uppercase letters and underscores."
            )

        if permission.permission_code != code and self.dao.get_by_code(code):
            raise HTTPException(status_code=400, detail=f"Permission code '{code}' already exists")

        return self.dao.update(permission, code, desc.strip())

    def delete_permission(self, permission_uuid: str):
        permission = self.dao.get_by_uuid(permission_uuid)
        if not permission:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Permission with ID {permission_uuid} not found"
            )

        try:
            # Manually clear relationships to avoid FK constraint errors
            permission.access_mappings.clear()
            permission.permission_groups.clear()

            self.dao.delete(permission)
        except Exception as e:
            self.db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to delete permission: {str(e)}"
            )

        return {"message": f"Permission with ID {permission_uuid} deleted successfully"}

    def delete_permission_cascade(self, permission_uuid: str):
        if not self.dao.get_by_uuid(permission_uuid):
            raise HTTPException(status_code=404, detail="Permission not found")
        permission_id = self.dao.get_by_uuid(permission_uuid).permission_id
        self.dao.delete_cascade(permission_id)

    def reassign_group(self, permission_uuid: int, group_uuid: int):
        if not self.dao.get_by_uuid(permission_uuid):
            raise HTTPException(status_code=404, detail="Permission not found")
        if not self.group_dao.get_group_by_uuid(group_uuid):
            raise HTTPException(status_code=404, detail="Group not found")
        permission_id = self.dao.get_by_uuid(permission_uuid).permission_id
        group_id = self.group_dao.get_group_by_uuid(group_uuid).group_id
        self.dao.update_group_mapping(permission_id, group_id)

    def list_unmapped_permissions(self):
        return self.dao.get_unmapped()

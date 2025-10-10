from sqlalchemy.orm import Session
from ...Data_Access_Layer.dao.group_dao import PermissionGroupDAO
from ...Data_Access_Layer.utils.dependency import SessionLocal  # SQLAlchemy session factory
from fastapi import HTTPException, status
from ..utils.generate_uuid7 import generate_uuid7
from ..utils.audit_decorator import audit_action_with_request

class PermissionGroupService:
    def __init__(self, db: Session):
        self.db = db
        self.dao = PermissionGroupDAO(self.db)


    def list_groups(self):
        return self.dao.get_all_groups()

    def get_group(self, group_id: int):
        return self.dao.get_group_by_uuid(group_id)
    

    @audit_action_with_request(
    action_type='CREATE',
    entity_type='Permission_Group',
    capture_old_data=False,
    capture_new_data=True,
    description='Created new permission group'
    )
    def create_group(self, group_name: str, created_by: int,**kwargs):
        existing = self.dao.get_group_by_name(group_name)
        if existing:
            raise ValueError("Group name already exists")

        result = self.dao.create_group(group_name, generate_uuid7(), created_by)
        if not result:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create permission group"
            )

        return result


    def update_group(self, group_uuid: str, group_name: str):
        default_group = self.dao.get_group_by_name("newly_created_permissions_group")
        df_group_uuid = default_group.group_uuid
        if group_uuid == df_group_uuid :
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot update the default permission group"
            )
        # Get current group
        current = self.dao.get_group_by_uuid(group_uuid)
        if not current:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Group not found"
            )

        # If the name is changing, check if another group already has it
        if current.group_name != group_name:
            existing = self.dao.get_group_by_name(group_name)
            if existing:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Group name already exists"
                )

        # Now safe to update
        updated_group = self.dao.update_group(group_uuid, group_name)
        return updated_group


    def delete_group(self, group_uuid: str):
        default_group = self.dao.get_group_by_name("newly_created_permissions_group")
        df_group_id = default_group.group_uuid
        if group_uuid == df_group_id :
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete the default permission group"
            )
        group = self.dao.get_group_by_uuid(group_uuid)
        if not group:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Permission group  not found"
            )

        try:
            # Clear dependent relationships first
            self.dao.clear_group_permissions(group.group_id)
            self.dao.clear_group_roles(group.group_id)

            # Delete the group itself
            if not self.dao.delete_group(group.group_id):
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to delete permission group"
                )
        except Exception as e:
            self.db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to delete permission group: {str(e)}"
            )

        return {"message": f"Permission group deleted successfully"}

    def delete_group_cascade(self, group_uuid: str):
        return self.dao.delete_group_cascade(group_uuid)

    def search_groups(self, keyword: str):
        return self.dao.search_groups(keyword)

    def list_unmapped_groups(self):
        return self.dao.get_unmapped_groups()

    def list_permissions_in_group(self, group_uuid: str):
        return self.dao.list_permissions_in_group(group_uuid)

    # services/permission_group_service.py

    def add_permissions_to_group(self, group_uuid: str, permission_uuids: list[str],assigned_by: int):
        group = self.dao.get_group_by_uuid(group_uuid)
        if not group:   
            raise HTTPException(status_code=404, detail="Permission group not found")
        group_id = group.group_id

        # Validate permission UUIDs and get their IDs
        permission_ids = []
        for puid in permission_uuids:
            perm = self.dao.get_permission_by_uuid(puid)
            if not perm:
                raise ValueError(f"Permission with UUID {puid} not found")
            permission_ids.append(perm.permission_id)
        
        # Add permissions to group
        new_mappings = self.dao.add_permissions_to_group(group_id, permission_ids,assigned_by)
        # Return full permission objects for response
        return self.dao.get_permissions_by_ids([m.permission_id for m in new_mappings])


    def remove_permissions_from_group(self, group_uuid: str, permission_uuids: list[str]):
        group = self.dao.get_group_by_uuid(group_uuid)
        if not group:   
            raise HTTPException(status_code=404, detail="Permission group not found")
        group_id = group.group_id

        # Validate permission UUIDs and get their IDs
        permission_ids = []
        for puid in permission_uuids:
            perm = self.dao.get_permission_by_uuid(puid)
            if not perm:
                raise ValueError(f"Permission with UUID {puid} not found")
            permission_ids.append(perm.permission_id)

        return self.dao.remove_permissions_from_group(group_id, permission_ids)

    def get_permission_by_code(self, code: str):
        return self.dao.get_permission_by_code(code)
    
    def get_unmapped_permissions(self, group_id: int):
        return self.dao.get_unmapped_permissions(group_id)

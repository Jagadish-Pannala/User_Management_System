from sqlalchemy.orm import Session
from ...Data_Access_Layer.dao.group_dao import PermissionGroupDAO
from ...Data_Access_Layer.utils.dependency import SessionLocal  # SQLAlchemy session factory
from fastapi import HTTPException, status

class PermissionGroupService:
    def __init__(self, db: Session):
        self.db = db
        self.dao = PermissionGroupDAO(self.db)


    def list_groups(self):
        return self.dao.get_all_groups()

    def get_group(self, group_id: int):
        return self.dao.get_group_by_id(group_id)

    def create_group(self, group_name: str):
        existing = self.dao.get_group_by_name(group_name)
        if existing:
            raise ValueError("Group name already exists")
        return self.dao.create_group(group_name)

    def update_group(self, group_id: int, group_name: str):
        # Get current group
        current = self.dao.get_group_by_id(group_id)
        if not current:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Group not found"
            )

        # If the name is changing, check if another group already has it
        if current != group_name:
            existing = self.dao.get_group_by_name(group_name)
            if existing:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Group name already exists"
                )

        # Now safe to update
        updated_group = self.dao.update_group(group_id, group_name)
        return {
            "message": "Group updated successfully",
            "group": updated_group
        }


    def delete_group(self, group_id: int):
        return self.dao.delete_group(group_id)

    def delete_group_cascade(self, group_id: int):
        return self.dao.delete_group_cascade(group_id)

    def search_groups(self, keyword: str):
        return self.dao.search_groups(keyword)

    def list_unmapped_groups(self):
        return self.dao.get_unmapped_groups()

    def list_permissions_in_group(self, group_id: int):
        return self.dao.list_permissions_in_group(group_id)

    # services/permission_group_service.py

    def add_permissions_to_group(self, group_id: int, permission_ids: list[int]):
        new_mappings = self.dao.add_permissions_to_group(group_id, permission_ids)
        # Return full permission objects for response
        return self.dao.get_permissions_by_ids([m.permission_id for m in new_mappings])


    def remove_permissions_from_group(self, group_id: int, permission_id: list[int]):
        return self.dao.remove_permissions_from_group(group_id, permission_id)

    def get_permission_by_code(self, code: str):
        return self.dao.get_permission_by_code(code)
    
    def get_unmapped_permissions(self, group_id: int):
        return self.dao.get_unmapped_permissions(group_id)

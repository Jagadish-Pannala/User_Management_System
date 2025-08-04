from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from sqlalchemy import or_
from ..models.models import Permission_Group, Permission_Group_Mapping, Permissions
from typing import List

class PermissionGroupDAO:
    def __init__(self, db: Session):
        self.db = db

    def get_all_groups(self):
        return self.db.query(Permission_Group).all()

    def get_group_by_id(self, group_id: int):
        return self.db.query(Permission_Group).filter_by(group_id=group_id).first()

    def get_group_by_name(self, name: str):
        return self.db.query(Permission_Group).filter_by(group_name=name).first()

    def search_groups(self, keyword: str):
        return self.db.query(Permission_Group).filter(Permission_Group.group_name.ilike(f"%{keyword}%")).all()

    def create_group(self, group_name: str):
        new_group = Permission_Group(group_name=group_name)
        self.db.add(new_group)
        self.db.commit()
        self.db.refresh(new_group)
        return new_group

    def update_group(self, group_id: int, group_name: str):
        group = self.get_group_by_id(group_id)
        if group:
            group.group_name = group_name
            self.db.commit()
            self.db.refresh(group)
        return group

    def delete_group(self, group_id: int):
        group = self.get_group_by_id(group_id)
        if group:
            self.db.delete(group)
            self.db.commit()
        return group

    def delete_group_cascade(self, group_id: int):
        self.db.query(Permission_Group_Mapping).filter_by(group_id=group_id).delete()
        group = self.get_group_by_id(group_id)
        if group:
            self.db.delete(group)
            self.db.commit()
        return True

    def get_unmapped_groups(self):
        mapped_ids = self.db.query(Permission_Group_Mapping.group_id).distinct()
        return self.db.query(Permission_Group).filter(~Permission_Group.group_id.in_(mapped_ids)).all()

    def list_permissions_in_group(self, group_id: int):
        rows = (
            self.db.query(Permissions.permission_id, Permissions.permission_code, Permissions.description)
            .join(Permission_Group_Mapping, Permissions.permission_id == Permission_Group_Mapping.permission_id)
            .filter(Permission_Group_Mapping.group_id == group_id)
            .all()
        )

        return [
            {
                "permission_id": row[0],
                "code": row[1],
                "description": row[2]
            }
            for row in rows
        ]




    def get_permission_by_code(self, code: str):
        return self.db.query(Permissions).filter_by(permission_code=code).first()

    # dao/permission_group_dao.py

    def add_permissions_to_group(self, group_id: int, permission_ids: list[int]):
        existing = (
            self.db.query(Permission_Group_Mapping.permission_id)
            .filter(
                Permission_Group_Mapping.group_id == group_id,
                Permission_Group_Mapping.permission_id.in_(permission_ids)
            )
            .all()
        )
        existing_ids = {e[0] for e in existing}

        new_mappings = [
            Permission_Group_Mapping(group_id=group_id, permission_id=pid)
            for pid in permission_ids if pid not in existing_ids
        ]

        if not new_mappings:
            raise ValueError("All selected permissions are already mapped to the group.")

        self.db.bulk_save_objects(new_mappings)
        self.db.commit()
        return new_mappings

    def get_permissions_by_ids(self, permission_ids: list[int]):
        return (
            self.db.query(Permissions)
            .filter(Permissions.permission_id.in_(permission_ids))
            .all()
        )


    def remove_permissions_from_group(self, group_id: int, permission_ids: list[int]):
        mappings = (
            self.db.query(Permission_Group_Mapping)
            .filter(
                Permission_Group_Mapping.group_id == group_id,
                Permission_Group_Mapping.permission_id.in_(permission_ids)
            )
            .all()
        )
        if not mappings:
            return False

        for mapping in mappings:
            self.db.delete(mapping)
        self.db.commit()
        return True
    
    def get_unmapped_permissions(self, group_id: int) -> List[Permissions]:
        subquery = (
            self.db.query(Permission_Group_Mapping.permission_id)
            .filter(Permission_Group_Mapping.group_id == group_id)
            .subquery()
        )
 
        query = self.db.query(Permissions).filter(Permissions.permission_id.notin_(subquery))
 
        return query.all()


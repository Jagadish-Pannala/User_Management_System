from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from ..models import models
from fastapi import HTTPException


class PermissionDAO:
    def __init__(self, db: Session):
        self.db = db

    def get_all(self):
        return self.db.query(models.Permissions).all()

    def get_by_id(self, permission_id: int):
        return self.db.query(models.Permissions).filter_by(permission_id=permission_id).first()

    def get_by_code(self, code: str):
        return self.db.query(models.Permissions).filter_by(permission_code=code).first()

    def get_unmapped(self):
        return self.db.query(models.Permissions).filter(
            ~models.Permissions.permission_id.in_(
                self.db.query(models.Permission_Group_Mapping.permission_id)
            )
        ).all()

    def create(self, permission_code: str, description: str):
        permission = models.Permissions(permission_code=permission_code, description=description)
        self.db.add(permission)
        self.db.commit()
        self.db.refresh(permission)
        return permission

    def delete(self, permission):
        self.db.delete(permission)
        self.db.commit()

    def delete_cascade(self, permission_id: int):
        self.db.query(models.Permission_Group_Mapping).filter_by(permission_id=permission_id).delete()
        self.db.query(models.AccessPointPermission).filter_by(permission_code=self.get_by_id(permission_id).permission_code).delete()
        self.db.query(models.Permissions).filter_by(permission_id=permission_id).delete()
        self.db.commit()

    def update(self, permission, code: str, desc: str):
        old_code = permission.permission_code

        # Update dependent table: AccessPointPermission
        if old_code != code:
            existing = self.db.query(models.Permissions)\
                .filter(models.Permissions.permission_code == code)\
                .filter(models.Permissions.permission_id != permission.permission_id)\
                .first()
            
            if existing:
                raise HTTPException(
                    status_code=400, 
                    detail=f"Permission code '{code}' already exists"
                )

        # Update Permissions table
        permission.permission_code = code
        permission.description = desc
        self.db.commit()
        self.db.refresh(permission)
        return permission
    
    


    def update_group_mapping(self, permission_id: int, group_id: int):
        self.db.query(models.Permission_Group_Mapping).filter_by(permission_id=permission_id).delete()
        self.db.add(models.Permission_Group_Mapping(permission_id=permission_id, group_id=group_id))
        self.db.commit()

    def map_to_group(self, permission_id: int, group_id: int):
        existing = self.db.query(models.Permission_Group_Mapping).filter_by(
            permission_id=permission_id,
            group_id=group_id
        ).first()
        if existing:
            raise ValueError("This permission is already mapped to the specified group.")
        self.db.add(models.Permission_Group_Mapping(permission_id=permission_id, group_id=group_id))
        self.db.commit()

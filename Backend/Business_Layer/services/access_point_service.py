from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from ...Data_Access_Layer.dao.access_point_dao import AccessPointDAO
from ...Api_Layer.interfaces.access_point import AccessPointCreate, AccessPointUpdate, AccessPointOut
from typing import List
from ...Data_Access_Layer.utils.dependency import SessionLocal


class AccessPointService:
    def __init__(self, db: Session = None):
        self.db: Session = db or SessionLocal()
        self.dao = AccessPointDAO(self.db)

    def create_access_point(self, data: AccessPointCreate):
        ap_dict = data.dict(exclude_unset=True)
        access_point = self.dao.create_access_point(**ap_dict)
        return {
            "access_id": access_point.access_id,
            "message": "Access point created successfully"
        }

    def list(self):
        access_points = self.dao.get_all_access_points()
        result = []
        for ap in access_points:
            permission_mapping = ap.permission_mappings[0] if ap.permission_mappings else None
            permission_id = permission_mapping.permission_id if permission_mapping else None
            permission_code = permission_mapping.permission.permission_code if permission_mapping and permission_mapping.permission else None

            result.append(AccessPointOut(
                access_id=ap.access_id,
                endpoint_path=ap.endpoint_path,
                method=ap.method,
                module=ap.module,
                is_public=ap.is_public,
                permission_id=permission_id,
                permission_code=permission_code
            ))
        return result


    def get(self, access_id: int):
        ap = self.dao.get_access_point_by_id(access_id)
        if not ap:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access point not found")
        
        permission_mapping = ap.permission_mappings[0] if ap.permission_mappings else None
        permission_id = permission_mapping.permission_id if permission_mapping else None
        permission_code = permission_mapping.permission.permission_code if permission_mapping and permission_mapping.permission else None

        return AccessPointOut(
            access_id=ap.access_id,
            endpoint_path=ap.endpoint_path,
            method=ap.method,
            module=ap.module,
            is_public=ap.is_public,
            permission_id=permission_id,
            permission_code=permission_code
        )


    def list_modules(self) -> List[str]:
        return self.dao.get_distinct_modules()

    def update(self, access_id: int, data: AccessPointUpdate):
        update_dict = data.dict(exclude_unset=True)
        updated_ap = self.dao.update_access_point(access_id, **update_dict)

        if not updated_ap:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access point not found")

        return AccessPointOut(
            access_id=updated_ap.access_id,
            endpoint_path=updated_ap.endpoint_path,
            method=updated_ap.method,
            module=updated_ap.module,
            is_public=updated_ap.is_public,
            permission_id=updated_ap.permission_mappings[0].permission_id if updated_ap.permission_mappings else None
        )

    def delete(self, access_id: int):
        success = self.dao.delete_access_point(access_id)
        if not success:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access point not found")
        return {"message": "Access point deleted successfully"}

    def map_permission(self, access_id: int, permission_id: int):
        ap = self.dao.get_access_point_by_id(access_id)
        if not ap:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access point not found")
        mapping = self.dao.create_access_permission_mapping(access_id, permission_id)
        return {
            "message": "Permission mapped successfully",
            "access_id": mapping.access_id,
            "permission_id": mapping.permission_id
        }

    def unmap_permission(self, access_id: int):
        success = self.dao.delete_mapping_by_access_id(access_id)
        if not success:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No mapping found to delete")
        return {"message": "Permission unmapped successfully"}
    
    def unmap_permission_both(self, access_id: int, permission_id: int) -> dict:
        success = self.dao.unmap_permission_dao(access_id, permission_id)
        if not success:
            return {"message": "Mapping not found or failed to delete"}
        return {"message": "Permission unmapped from access point successfully"}
    
    def get_unmapped_access_points(self):
        all_aps = self.dao.get_all_access_points()
        return [
            AccessPointOut(
                access_id=ap.access_id,
                endpoint_path=ap.endpoint_path,
                method=ap.method,
                module=ap.module,
                is_public=ap.is_public,
                permission_code= None,
                permission_id= None
                
            )
            for ap in all_aps if not ap.permission_mappings
        ]
    
    def get_unmapped_permissions(self):
        permissions = self.dao.get_unmapped_permissions()
        return [
            {
                "permission_id": perm.permission_id,
                "code": perm.permission_code,
                "description": perm.description
            }
            for perm in permissions
        ]


from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from ...Data_Access_Layer.dao.access_point_dao import AccessPointDAO
from ...Api_Layer.interfaces.access_point import AccessPointCreate, AccessPointUpdate, AccessPointOut
from typing import List
from ...Data_Access_Layer.utils.dependency import SessionLocal
from sqlalchemy.exc import IntegrityError
import re
from ..utils.generate_uuid7 import generate_uuid7
from ...Data_Access_Layer.dao.permission_dao import PermissionDAO


class AccessPointService:
    def __init__(self, db: Session = None):
        self.db: Session = db or SessionLocal()
        self.dao = AccessPointDAO(self.db)
        self.permission_dao = PermissionDAO(self.db)

    # def create_access_point(self, data: AccessPointCreate):
    #     ap_dict = data.dict(exclude_unset=True)
    #     access_point = self.dao.create_access_point(**ap_dict)
    #     return {
    #         "access_id": access_point.access_id,
    #         "message": "Access point created successfully"
    #     }

    def normalize_endpoint(self, endpoint: str) -> str:
        """
        Convert endpoint with {params} into regex pattern.
        Static endpoints are returned unchanged.
        """
        if "{" not in endpoint:  # static path
            return endpoint

        # Replace {param} with a named regex group (allowing digits/letters/_/-)
        pattern = re.sub(r"\{(\w*)\}", r"([^/]+)", endpoint)

        return "^" + pattern + "$"

    def create_access_point(self, data: AccessPointCreate, created_by_user_id: int):
        ap_dict = data.dict(exclude_unset=True)
        
        # Normalize endpoint_path before saving
        ap_dict["regex_pattern"] = self.normalize_endpoint(ap_dict["endpoint_path"])
        ap_dict["created_by"] = created_by_user_id
        ap_dict["access_uuid"] = generate_uuid7()  
        
        
        existing = self.dao.get_by_endpoint_path(ap_dict.get("endpoint_path"))

        if existing and existing.method.upper() == ap_dict["method"].upper():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Access point with this endpoint_path AND method '{ap_dict['method']}' already exists"
            )
        
        try:
            access_point = self.dao.create_access_point(**ap_dict)
        except IntegrityError as e:
            print("IntegrityError details:", e.orig) 
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid data or constraint violation"
            ) from e
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create access point"
            ) from e

        return {
            "access_uuid": access_point.access_uuid,
            "message": "Access point created successfully"
        }

    def list(self):
        access_points = self.dao.get_all_access_points()
        result = []
        for ap in access_points:
            permission_mapping = ap.permission_mappings[0] if ap.permission_mappings else None
            permission_code = permission_mapping.permission.permission_code if permission_mapping and permission_mapping.permission else None
            permission_uuid = permission_mapping.permission.permission_uuid if permission_mapping and permission_mapping.permission else None

            result.append(AccessPointOut(
                access_uuid=ap.access_uuid,
                endpoint_path=ap.endpoint_path,
                method=ap.method,
                module=ap.module,
                is_public=ap.is_public,
                permission_uuid=permission_uuid,
                permission_code=permission_code,
                created_at=ap.created_at,
                updated_at=ap.updated_at
            ))
        return result


    def get(self, access_uuid: str):
        ap = self.dao.get_access_point_by_uuid(access_uuid)
        if not ap:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access point not found")
        
        permission_mapping = ap.permission_mappings[0] if ap.permission_mappings else None
        permission_code = permission_mapping.permission.permission_code if permission_mapping and permission_mapping.permission else None
        permission_uuid = permission_mapping.permission.permission_uuid if permission_mapping and permission_mapping.permission else None

        return AccessPointOut(
            access_uuid=ap.access_uuid,
            endpoint_path=ap.endpoint_path,
            method=ap.method,
            module=ap.module,
            is_public=ap.is_public,
            permission_uuid=permission_uuid,
            permission_code=permission_code,
            created_at=ap.created_at,
            updated_at=ap.updated_at
        )


    def list_modules(self) -> List[str]:
        return self.dao.get_distinct_modules()

    # def update(self, access_id: int, data: AccessPointUpdate):
    #     update_dict = data.dict(exclude_unset=True)
    #     updated_ap = self.dao.update_access_point(access_id, **update_dict)

    #     if not updated_ap:
    #         raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access point not found")

    #     return AccessPointOut(
    #         access_id=updated_ap.access_id,
    #         endpoint_path=updated_ap.endpoint_path,
    #         method=updated_ap.method,
    #         module=updated_ap.module,
    #         is_public=updated_ap.is_public,
    #         permission_id=updated_ap.permission_mappings[0].permission_id if updated_ap.permission_mappings else None
    #     )

    def update(self, access_uuid: str, data: AccessPointUpdate):
        update_dict = data.dict(exclude_unset=True)

        # --- Fetch the existing access point ---
        current_ap = self.dao.get_access_point_by_uuid(access_uuid)
        if not current_ap:
            raise HTTPException(status_code=404, detail="Access point not found")

        # --- Handle permission logic ---
        new_permission_code = update_dict.get("permission_code", None)

        if "permission_code" in update_dict:
            if new_permission_code == "Null" or new_permission_code is None or new_permission_code == "":
                # ✅ User wants to delete permission mapping
                self.dao.update_access_point_permission(current_ap.access_id, "Null")
            else:
                # ❌ User tried to change/add permission (not allowed)
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="You can only delete permission mappings, not modify or add new ones"
                )
            # Remove permission_code from update_dict so it's not updated in AccessPoint
            del update_dict["permission_code"]

        # --- Handle endpoint/method changes ---
        if 'endpoint_path' in update_dict or 'method' in update_dict:
            new_endpoint = update_dict.get('endpoint_path', current_ap.endpoint_path)
            new_method = update_dict.get('method', current_ap.method)
            regex_pattern = self.normalize_endpoint(new_endpoint)
            update_dict['regex_pattern'] = regex_pattern

            # Check for duplicate (endpoint_path + method)
            existing = self.dao.get_access_point_by_path_and_method(new_endpoint, new_method)
            if existing and existing.access_uuid != access_uuid:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Another access point with this endpoint and method already exists"
                )
        else:
            new_endpoint = current_ap.endpoint_path
            new_method = current_ap.method

        # --- Other fields (module, is_public) ---
        new_module = update_dict.get('module', current_ap.module)
        new_is_public = update_dict.get('is_public', current_ap.is_public)

        # --- Perform AccessPoint update ---
        updated_ap = self.dao.update_access_point(current_ap.access_id, **update_dict)

        # --- Prepare updated permission code for response ---
        permission_code = self.dao.get_permission_code_by_access_id(current_ap.access_id)

        # --- Build and return response ---
        return AccessPointOut(
            access_uuid=access_uuid,
            endpoint_path=new_endpoint,
            method=new_method,
            module=new_module,
            is_public=new_is_public,
            permission_code=permission_code
        )




    def delete(self, access_uuid: str):
        access_point = self.dao.get_access_point_by_uuid(access_uuid)
        if not access_point:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access point not found") 
        access_id = access_point.access_id
        success = self.dao.delete_access_point(access_id)
        if not success:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access point not found")
        return {"message": "Access point deleted successfully"}

    def map_permission(self, access_uuid: str, permission_uuid: str, assigned_by: int):
        access_point = self.dao.get_access_point_by_uuid(access_uuid)
        if not access_point:    
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access point not found")
        access_id = access_point.access_id

        permission = self.permission_dao.get_by_uuid(permission_uuid)
        if not permission:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Permission not found")   
        permission_id = permission.permission_id

        ap = self.dao.get_access_point_by_id(access_id)
        if not ap:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access point not found")
        mapping = self.dao.create_access_permission_mapping(access_id, permission_id, assigned_by=assigned_by)
        return {
            "message": "Permission mapped successfully",
            "access_uuid": access_point.access_uuid,
            "permission_uuid": permission.permission_uuid
        }

    def unmap_permission(self, access_id: int):
        success = self.dao.delete_mapping_by_access_id(access_id)
        if not success:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No mapping found to delete")
        return {"message": "Permission unmapped successfully"}
    
    def unmap_permission_both(self, access_uuid: str, permission_uuid: str) -> dict:
        access_point = self.dao.get_access_point_by_uuid(access_uuid)
        if not access_point:    
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access point not found")
        access_id = access_point.access_id

        permission = self.permission_dao.get_by_uuid(permission_uuid)
        if not permission:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Permission not found")   
        permission_id = permission.permission_id

        success = self.dao.unmap_permission_dao(access_id, permission_id)
        if not success:
            return {"message": "Mapping not found or failed to delete"}
        return {"message": "Permission unmapped from access point successfully"}
    
    def get_unmapped_access_points(self):
        all_aps = self.dao.get_all_access_points()
        return [
            AccessPointOut(
                access_uuid=ap.access_uuid,
                endpoint_path=ap.endpoint_path,
                method=ap.method,
                module=ap.module,
                is_public=ap.is_public,
                permission_code= None,
                permission_uuid= None,
                created_at=ap.created_at,
                updated_at=ap.updated_at
                
            )
            for ap in all_aps if not ap.permission_mappings
        ]
    
    def get_unmapped_permissions(self):
        permissions = self.dao.get_unmapped_permissions()
        return [
            {
                "permission_uuid": perm.permission_uuid,
                "code": perm.permission_code,
                "description": perm.description
            }
            for perm in permissions
        ]


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
from ..utils.audit_decorator import audit_action_with_request


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
            return None

        # Replace {param} with a named regex group (allowing digits/letters/_/-)
        pattern = re.sub(r"\{(\w*)\}", r"([^/]+)", endpoint)

        return "^" + pattern + "$"

    @audit_action_with_request(
    action_type='CREATE',
    entity_type='AccessPoint',
    capture_new_data=True,
    description='Created new access point'
    )
    def create_access_point(self, data: AccessPointCreate, created_by_user_id: int, **kwargs):
        audit_data = kwargs.get('audit_data', {})
        
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

        # Set entity_id for audit (since we're returning a dict, not the object)
        audit_data['entity_id'] = access_point.access_id  # or whatever your PK is
        audit_data['new_data'] = {
            "access_id": access_point.access_id,
            "access_uuid": access_point.access_uuid,
            "endpoint_path": access_point.endpoint_path,
            "method": access_point.method,
            "module": access_point.module,
            "is_public": access_point.is_public,
            "created_by": access_point.created_by,
            "created_at": str(access_point.created_at)
        }
        
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

    @audit_action_with_request(
    action_type='UPDATE',
    entity_type='AccessPoint',
    capture_old_data=False,  # Manual capture
    capture_new_data=False,  # Manual capture
    description='Updated access point'
    )
    def update(self, access_uuid: str, data: AccessPointUpdate, **kwargs):
        audit_data = kwargs.get('audit_data', {})
        
        update_dict = data.dict(exclude_unset=True)
        
        # --- Fetch the existing access point ---
        current_ap = self.dao.get_access_point_by_uuid(access_uuid)
        if not current_ap:
            raise HTTPException(status_code=404, detail="Access point not found")
        
        # Set entity_id for audit
        audit_data['entity_id'] = current_ap.access_id
        
        # ✅ CREATE A SNAPSHOT of old values BEFORE any changes
        old_permission_code = self.dao.get_permission_code_by_access_id(current_ap.access_id)
        old_snapshot = {
            "access_uuid": str(current_ap.access_uuid),
            "endpoint_path": current_ap.endpoint_path,
            "method": current_ap.method,
            "module": current_ap.module,
            "is_public": current_ap.is_public,
            "regex_pattern": current_ap.regex_pattern,
            "permission_code": old_permission_code
        }
        
        audit_data['old_data'] = old_snapshot
        
        # --- Handle permission logic ---
        permission_changed = False
        new_permission_code = update_dict.get("permission_code", None)
        if "permission_code" in update_dict:
            if new_permission_code == "Null" or new_permission_code is None or new_permission_code == "":
                # ✅ User wants to delete permission mapping
                self.dao.update_access_point_permission(current_ap.access_id, "Null")
                permission_changed = True
                new_permission_code = None
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
        if not permission_changed:
            permission_code = self.dao.get_permission_code_by_access_id(current_ap.access_id)
        else:
            permission_code = new_permission_code
        
        # ✅ Compare against the OLD SNAPSHOT, not current_ap
        changes = {}
        if updated_ap.endpoint_path != old_snapshot['endpoint_path']:
            changes['endpoint_path'] = {
                "old": old_snapshot['endpoint_path'],
                "new": updated_ap.endpoint_path
            }
        if updated_ap.method != old_snapshot['method']:
            changes['method'] = {
                "old": old_snapshot['method'],
                "new": updated_ap.method
            }
        if updated_ap.module != old_snapshot['module']:
            changes['module'] = {
                "old": old_snapshot['module'],
                "new": updated_ap.module
            }
        if updated_ap.is_public != old_snapshot['is_public']:
            changes['is_public'] = {
                "old": old_snapshot['is_public'],
                "new": updated_ap.is_public
            }
        if 'regex_pattern' in update_dict and updated_ap.regex_pattern != old_snapshot['regex_pattern']:
            changes['regex_pattern'] = {
                "old": old_snapshot['regex_pattern'],
                "new": updated_ap.regex_pattern
            }
        if permission_changed and old_permission_code != permission_code:
            changes['permission_code'] = {
                "old": old_permission_code,
                "new": permission_code
            }
        
        audit_data['new_data'] = changes if changes else None
        
        # --- Build and return response ---
        return AccessPointOut(
            access_uuid=access_uuid,
            endpoint_path=new_endpoint,
            method=new_method,
            module=new_module,
            is_public=new_is_public,
            permission_code=permission_code
        )



    @audit_action_with_request(
    action_type='DELETE',
    entity_type='AccessPoint',
    get_entity_id=lambda self, access_uuid, *args, **kwargs: (
        self.dao.get_access_point_by_uuid(access_uuid).access_id
        if self.dao.get_access_point_by_uuid(access_uuid)
        else None
    ),
    capture_old_data=True,
    capture_new_data=False,
    description='Deleted an access point'
    )
    def delete(self, access_uuid: str, **kwargs):
        access_point = self.dao.get_access_point_by_uuid(access_uuid)
        if not access_point:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Access point with UUID {access_uuid} not found"
            )
        audit_data = kwargs.get('audit_data', {})
        audit_data['old_data'] = {
            "access_id": access_point.access_id,
            "access_uuid": access_point.access_uuid,
            "endpoint_path": access_point.endpoint_path,
            "method": access_point.method,
            "module": access_point.module,
            "is_public": access_point.is_public,
            "created_by": access_point.created_by,
            "created_at": str(access_point.created_at)
        }
        success = self.dao.delete_access_point(access_point.access_id)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to delete access point"
            )

        return {"message": f"Access point  deleted successfully"}

    @audit_action_with_request(
    action_type='Update',
    entity_type='AccessPointPermission',
    capture_old_data=False,
    capture_new_data=False,
    description='Mapped a permission to an access point'
    )
    def map_permission(self, access_uuid: str, permission_uuid: str, assigned_by: int, **kwargs):
        access_point = self.dao.get_access_point_by_uuid(access_uuid)
        if not access_point:    
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access point not found")
        access_id = access_point.access_id

        audit_data = kwargs.get('audit_data', {})
        audit_data['entity_id'] = access_id

        permission = self.permission_dao.get_by_uuid(permission_uuid)
        if not permission:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Permission not found")   
        permission_id = permission.permission_id

        ap = self.dao.get_access_point_by_id(access_id)
        if not ap:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access point not found")
        mapping = self.dao.create_access_permission_mapping(access_id, permission_id, assigned_by=assigned_by)

        audit_data['new_data'] = { "assigned_permission" :{
            "access_uuid": access_uuid,
            "permission_uuid": permission_uuid,
            "permission_code": permission.permission_code,
            "assigned_by": assigned_by
        } }
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
    
    @audit_action_with_request(
    action_type='Update',
    entity_type='AccessPointPermission',
    description='Unmapped a permission from an access point'
)
    def unmap_permission_both(self, access_uuid: str, permission_uuid: str,**kwargs) -> dict:
        audit_data = kwargs.get('audit_data', {})
        access_point = self.dao.get_access_point_by_uuid(access_uuid)
        if not access_point:    
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access point not found")
        access_id = access_point.access_id
        audit_data['entity_id'] = access_id      
        permission = self.permission_dao.get_by_uuid(permission_uuid)
        if not permission:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Permission not found")   
        permission_id = permission.permission_id

        audit_data['entity_id'] = access_id
        audit_data['old_data'] = {
            "access_uuid": access_point.access_uuid,
            "endpoint_path": access_point.endpoint_path,
            "method": access_point.method,
            "module": access_point.module,
            "is_public": access_point.is_public,
            "permission_uuid": permission.permission_uuid,
            "permission_code": permission.permission_code
        }

        success = self.dao.unmap_permission_dao(access_id, permission_id)
        if not success:
            return {"message": "Mapping not found or failed to delete"}
        audit_data['new_data'] = {"removed_mapping": {
            "permission_uuid": permission.permission_uuid,
            "permission_code": permission.permission_code
        } }
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


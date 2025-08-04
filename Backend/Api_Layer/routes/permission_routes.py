from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ...Business_Layer.services.permission_service import PermissionService
from ..interfaces.permission_management import (
    PermissionBase,
    PermissionOut,
    PermissionCreate,
    PermissionGroupUpdate,
    PermissionCreateU,
    PermissionResponse
)
from ..JWT.jwt_validator.auth.dependencies import get_current_user
from ...Data_Access_Layer.utils.dependency import get_db

router = APIRouter()

# Dependency injection for the service
def get_permission_service(db: Session = Depends(get_db)):
    return PermissionService(db)


@router.get("/", response_model=list[PermissionOut])
def list_permissions(
    current_user: dict = Depends(get_current_user),
    service: PermissionService = Depends(get_permission_service)
):
    return service.list_permissions()


@router.get("/unmapped")
def get_unmapped_permissions(
    current_user: dict = Depends(get_current_user),
    service: PermissionService = Depends(get_permission_service)
):
    return service.list_unmapped_permissions()


@router.get("/{permission_id}", response_model=PermissionOut)
def get_permission(
    permission_id: int,
    current_user: dict = Depends(get_current_user),
    service: PermissionService = Depends(get_permission_service)
):
    return service.get_permission(permission_id)


@router.post("", status_code=201)
def create_permission(
    payload: PermissionCreate,
    current_user: dict = Depends(get_current_user),
    service: PermissionService = Depends(get_permission_service)
):
    return service.create_permission_minimal(
        payload.permission_code, payload.description, payload.group_id
    )


@router.post("/", status_code=201)
def create_permission_basic(
    permission: PermissionCreateU,
    current_user: dict = Depends(get_current_user),
    service: PermissionService = Depends(get_permission_service)
):
    return service.create_permission_minimal(
        permission.permission_code, permission.description
    )


@router.put("/{permission_id}", response_model=dict)
def update_permission(
    permission_id: int,
    payload: PermissionBase,
    current_user: dict = Depends(get_current_user),
    service: PermissionService = Depends(get_permission_service)
):
    result = service.update_permission(
        permission_id, payload.permission_code, payload.description
    )
    
    # Convert SQLAlchemy object to Pydantic model
    permission_data = PermissionResponse.from_orm(result) if hasattr(PermissionResponse, 'from_orm') else PermissionResponse.model_validate(result)
    
    return {
        "message": "Permission updated successfully",
        "data": permission_data.dict()
    }


@router.delete("/{permission_id}")
def delete_permission(
    permission_id: int,
    current_user: dict = Depends(get_current_user),
    service: PermissionService = Depends(get_permission_service)
):
    service.delete_permission(permission_id)
    return {"message": "Permission deleted successfully"}


@router.delete("/cascading/{permission_id}")
def delete_permission_cascade(
    permission_id: int,
    current_user: dict = Depends(get_current_user),
    service: PermissionService = Depends(get_permission_service)
):
    service.delete_permission_cascade(permission_id)
    return {"message": "Permission and all associations deleted successfully"}


@router.put("/{permission_id}/group")
def update_permission_group(
    permission_id: int,
    payload: PermissionGroupUpdate,
    current_user: dict = Depends(get_current_user),
    service: PermissionService = Depends(get_permission_service)
):
    service.reassign_group(permission_id, payload.group_id)
    return {"message": "Permission reassigned to new group successfully"}



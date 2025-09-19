from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List
from sqlalchemy.orm import Session

from ..interfaces.role_mangement import RoleBase, RoleOut, RolePermissionGroupUpdate,RoleGroupRequest
from ..JWT.jwt_validator.auth.dependencies import get_current_user, admin_required
from ...Business_Layer.services.role_service import RoleService
from ...Data_Access_Layer.utils.dependency import get_db

router = APIRouter()

def get_role_service(db: Session = Depends(get_db)):
    return RoleService(db)


# --- Basic Role CRUD ---
@router.get("/")
def admin_home(current_user: dict = Depends(admin_required)):
    return {"message": "Role Management Route"}

@router.get("", response_model=List[RoleOut])
def list_roles(
    service: RoleService = Depends(get_role_service),
    current_user: dict = Depends(admin_required)
):
    return service.list_roles()

@router.get("/{role_id}", response_model=RoleOut)
def get_role(
    role_id: int,
    service: RoleService = Depends(get_role_service),
    current_user: dict = Depends(admin_required)
):
    return service.get_role_by_id(role_id)

@router.post("", response_model=RoleOut)
def create_role(
    role: RoleBase,
    service: RoleService = Depends(get_role_service),
    current_user: dict = Depends(admin_required)
):
    return service.create_role(role)

@router.put("/{role_id}", response_model=RoleOut)
def update_role(
    role_id: int,
    role: RoleBase,
    service: RoleService = Depends(get_role_service),
    current_user: dict = Depends(admin_required)
):
    return service.update_role(role_id, role)

@router.delete("/{role_id}")
def delete_role(
    role_id: int,
    service: RoleService = Depends(get_role_service),
    current_user: dict = Depends(admin_required)
):
    return service.delete_role(role_id)


# --- Permission Group Management for Roles ---
@router.get("/{role_id}/permissions")
def get_permissions_by_role(
    role_id: int,
    service: RoleService = Depends(get_role_service),
    current_user: dict = Depends(admin_required)
):
    return service.get_permissions_by_role(role_id)

@router.get("/{role_id}/groups")
def get_permission_groups_by_role(
    role_id: int,
    service: RoleService = Depends(get_role_service),
    current_user: dict = Depends(admin_required)
):
    return service.get_permission_groups_by_role(role_id)

@router.put("/{role_id}/groups")
def update_permission_groups_for_role(
    role_id: int,
    payload: RoleGroupRequest,
    service: RoleService = Depends(get_role_service),
    current_user: dict = Depends(admin_required)
):
    return service.update_permission_groups_for_role(role_id, payload.group_ids)

@router.post("/{role_id}/groups")
def add_permission_groups_to_role(
    role_id: int,
    payload: RoleGroupRequest,
    service: RoleService = Depends(get_role_service),
    current_user: dict = Depends(admin_required)
):
    return service.add_permission_groups_to_role(role_id, payload.group_ids)

@router.delete("/{role_id}/groups/{group_id}")
def remove_permission_group_from_role(
    role_id: int,
    group_id: int,
    service: RoleService = Depends(get_role_service),
    current_user: dict = Depends(admin_required)
):
    return service.remove_permission_group_from_role(role_id, group_id)

@router.get("/{role_id}/available-groups")
def get_unassigned_permission_groups_for_role(
    role_id: int,
    service: RoleService = Depends(get_role_service),
    current_user: dict = Depends(admin_required)
):
    return service.get_unassigned_permission_groups(role_id)

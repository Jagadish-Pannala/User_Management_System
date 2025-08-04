from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List
from ..interfaces.permissiongroup import GroupBase, GroupOut, PermissionInGroupwithId
from ...Business_Layer.services.permission_group_service import PermissionGroupService
from ...Business_Layer.utils.permission_check import permission_required
from ..JWT.jwt_validator.auth.dependencies import get_current_user
from ...Data_Access_Layer.utils.dependency import get_db
from sqlalchemy.orm import Session
from ..interfaces.permission_management import  PermissionOut

router = APIRouter()

# Dependency injector for PermissionGroupService
def get_permission_group_service(db: Session = Depends(get_db)):
    return PermissionGroupService(db)


@router.get("/permission-groups/unmapped", response_model=List[GroupOut])
def get_unmapped_groups(
    service: PermissionGroupService = Depends(get_permission_group_service),
    current_user: dict = Depends(get_current_user)
):
    return service.list_unmapped_groups()


@router.get("/", dependencies=[Depends(permission_required)])
def admin_home():
    return {"message": "Group Management Route"}


@router.get("", response_model=List[GroupOut])
def list_groups(
    keyword: str = Query(default="", description="Search keyword"),
    service: PermissionGroupService = Depends(get_permission_group_service),
    current_user: dict = Depends(get_current_user)
):
    if keyword:
        return service.search_groups(keyword)
    return service.list_groups()


@router.get("/{group_id}", response_model=GroupOut)
def get_group(
    group_id: int,
    service: PermissionGroupService = Depends(get_permission_group_service),
    current_user: dict = Depends(get_current_user)
):
    group = service.get_group(group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    return group


@router.post("", response_model=GroupOut, status_code=201)
def create_group(
    group: GroupBase,
    service: PermissionGroupService = Depends(get_permission_group_service),
    current_user: dict = Depends(get_current_user)
):
    try:
        return service.create_group(group.group_name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/{group_id}", response_model=GroupOut)
def update_group(
    group_id: int,
    group: GroupBase,
    service: PermissionGroupService = Depends(get_permission_group_service),
    current_user: dict = Depends(get_current_user)
):
    updated = service.update_group(group_id, group.group_name)
    if not updated:
        raise HTTPException(status_code=404, detail="Group not found")
    return updated


@router.delete("/{group_id}", status_code=204)
def delete_group(
    group_id: int,
    cascade: bool = Query(default=False, description="Delete group and its mappings"),
    service: PermissionGroupService = Depends(get_permission_group_service),
    current_user: dict = Depends(get_current_user)
):
    deleted = service.delete_group_cascade(group_id) if cascade else service.delete_group(group_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Group not found")


@router.get("/{group_id}/permissions", response_model=List[PermissionInGroupwithId])
def get_permissions_in_group(
    group_id: int,
    service: PermissionGroupService = Depends(get_permission_group_service),
    current_user: dict = Depends(get_current_user)
):
    group = service.get_group(group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Permission group not found")

    return service.list_permissions_in_group(group_id)




@router.post("/{group_id}/permissions", response_model=List[PermissionOut])
def add_permissions_to_group(
    group_id: int,
    permission_ids: List[int],
    service: PermissionGroupService = Depends(get_permission_group_service),
    current_user: dict = Depends(get_current_user)
):
    try:
        return service.add_permissions_to_group(group_id, permission_ids)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))




@router.delete("/{group_id}/permissions", status_code=200)
def remove_permissions_from_group(
    group_id: int,
    permission_ids: List[int],  # query param or body
    service: PermissionGroupService = Depends(get_permission_group_service),
    current_user: dict = Depends(get_current_user)
):
    removed = service.remove_permissions_from_group(group_id, permission_ids)
    if not removed:
        raise HTTPException(status_code=404, detail="No matching permission mappings found.")
    
    return {"message": "Permissions removed successfully"}

@router.get("/{group_id}/unmapped-permissions", response_model=List[PermissionOut])
def get_unmapped_permissions_for_group(
    group_id: int,
    service: PermissionGroupService = Depends(get_permission_group_service),
    current_user: dict = Depends(get_current_user)
):
    group = service.get_group(group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
 
    return service.get_unmapped_permissions(group_id)


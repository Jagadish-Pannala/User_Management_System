from fastapi import APIRouter, Depends, HTTPException, Query,Request
from typing import List
from ..interfaces.permissiongroup import GroupBase, GroupOut, PermissionInGroupwithId,GroupIn
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


@router.get("/{group_uuid}", response_model=GroupOut)
def get_group(
    group_uuid: str,
    service: PermissionGroupService = Depends(get_permission_group_service),
    current_user: dict = Depends(get_current_user)
):
    group = service.get_group(group_uuid)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    return group


@router.post("", response_model=GroupOut, status_code=201)
def create_group(
    group: GroupIn,
    request: Request,
    service: PermissionGroupService = Depends(get_permission_group_service),
    current_user: dict = Depends(get_current_user)
):
    try:
        return service.create_group(group.group_name,current_user['user_id'],request=request,current_user=current_user)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/{group_uuid}", response_model=GroupOut)
def update_group(
    group_uuid: str,
    group: GroupIn,
    request: Request,
    service: PermissionGroupService = Depends(get_permission_group_service),
    current_user: dict = Depends(get_current_user)
):
    updated = service.update_group(group_uuid, group.group_name,request=request,current_user=current_user)
    if not updated:
        raise HTTPException(status_code=404, detail="Group not found")
    return updated


@router.delete("/{group_uuid}", status_code=204)
def delete_group(
    group_uuid: str,
    request: Request,
    cascade: bool = Query(default=False, description="Delete group and its mappings"),
    service: PermissionGroupService = Depends(get_permission_group_service),
    current_user: dict = Depends(get_current_user)
):
    deleted = service.delete_group_cascade(group_uuid) if cascade else service.delete_group(group_uuid,request=request,current_user=current_user)
    if not deleted:
        raise HTTPException(status_code=404, detail="Group not found")


@router.get("/{group_uuid}/permissions", response_model=List[PermissionInGroupwithId])
def get_permissions_in_group(
    group_uuid: str,
    service: PermissionGroupService = Depends(get_permission_group_service),
    current_user: dict = Depends(get_current_user)
):
    group = service.get_group(group_uuid)
    if not group:
        raise HTTPException(status_code=404, detail="Permission group not found")

    return service.list_permissions_in_group(group_uuid)




@router.post("/{group_uuid}/permissions", response_model=List[PermissionOut])
def add_permissions_to_group(
    group_uuid: str,
    permission_uuids: List[str],
    request: Request,
    service: PermissionGroupService = Depends(get_permission_group_service),
    current_user: dict = Depends(get_current_user)
):
    try:
        return service.add_permissions_to_group(group_uuid, permission_uuids,current_user['user_id'],request=request,current_user=current_user)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))




@router.delete("/{group_uuid}/permissions", status_code=200)
def remove_permissions_from_group(
    group_uuid: str,
    permission_uuids: List[str],  # query param or body
    request: Request,
    service: PermissionGroupService = Depends(get_permission_group_service),
    current_user: dict = Depends(get_current_user)
):
    removed = service.remove_permissions_from_group(group_uuid, permission_uuids,request=request,current_user=current_user)
    if not removed:
        raise HTTPException(status_code=404, detail="No matching permission mappings found.")
    
    return {"message": "Permissions removed successfully"}

@router.get("/{group_uuid}/unmapped-permissions", response_model=List[PermissionOut])
def get_unmapped_permissions_for_group(
    group_uuid: str,
    service: PermissionGroupService = Depends(get_permission_group_service),
    current_user: dict = Depends(get_current_user)
):
    group = service.get_group(group_uuid)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
 
    return service.get_unmapped_permissions(group.group_id)


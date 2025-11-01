from fastapi import APIRouter, HTTPException, Depends,Request, UploadFile, File
from sqlalchemy.orm import Session
from typing import List

from ..interfaces.access_point import (
    AccessPointCreate,
    AccessPointUpdate,
    AccessPointOut,
    CreateAPResponse,PermissionMappingIn,BulkCreateAPResponse
)
from ...Business_Layer.services.access_point_service import AccessPointService
from ...Data_Access_Layer.utils.dependency import get_db
from ..JWT.jwt_validator.auth.dependencies import get_current_user

router = APIRouter()


def get_access_point_service(db: Session = Depends(get_db)) -> AccessPointService:
    return AccessPointService(db)


@router.get("/modules", response_model=List[str])
def get_all_modules(
    _: dict = Depends(get_current_user),
    service: AccessPointService = Depends(get_access_point_service)
):
    return service.list_modules()

@router.get("/unmapped-access-points", response_model=List[AccessPointOut])
def get_unmapped_access_points(
    _: dict = Depends(get_current_user),
    service: AccessPointService = Depends(get_access_point_service)
):
    return service.get_unmapped_access_points()

@router.get("/unmapped-permissions")
def get_unmapped_permissions(
    _: dict = Depends(get_current_user),
    service: AccessPointService = Depends(get_access_point_service)
):
    return service.get_unmapped_permissions()


@router.post("/", response_model=CreateAPResponse)
def create_ap(
    data: AccessPointCreate,
    request: Request,
    current_user: dict = Depends(get_current_user),
    service: AccessPointService = Depends(get_access_point_service)
):
    return service.create_access_point(data,created_by_user_id=current_user['user_id'],request=request,current_user=current_user)

@router.post("/bulk-access-points-create", response_model=BulkCreateAPResponse)
def bulk_create_ap(
    request: Request,
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user),
    service: AccessPointService = Depends(get_access_point_service)
):
    return service.bulk_create_access_points(file=file,created_by_user_id=current_user['user_id'],request=request,current_user=current_user)


@router.get("/", response_model=List[AccessPointOut])
def list_aps(
    _: dict = Depends(get_current_user),
    service: AccessPointService = Depends(get_access_point_service)
):
    return service.list()


@router.get("/{access_uuid}", response_model=AccessPointOut)
def get_ap(
    access_uuid: str,
    _: dict = Depends(get_current_user),
    service: AccessPointService = Depends(get_access_point_service)
):
    return service.get(access_uuid)


@router.put("/{access_uuid}", response_model=AccessPointOut)
def update_ap(
    access_uuid: str,
    data: AccessPointUpdate,
    request: Request,
    current_user: dict = Depends(get_current_user),
    service: AccessPointService = Depends(get_access_point_service)
):
    return service.update(access_uuid, data,request=request,current_user=current_user)


@router.delete("/{access_uuid}")
def delete_ap(
    access_uuid: str,
    request: Request,
    current_user: dict = Depends(get_current_user),
    service: AccessPointService = Depends(get_access_point_service)
):
    return service.delete(access_uuid,request=request,current_user=current_user)


@router.post("/{access_uuid}/map-permission/{permission_uuid}")
def map_permission(
    access_uuid: str,
    permission_uuid: str,
    request: Request,
    current_user: dict = Depends(get_current_user),
    service: AccessPointService = Depends(get_access_point_service)
):
    return service.map_permission(access_uuid, permission_uuid,current_user['user_id'],request=request,current_user=current_user)

@router.post("/access-point-map-permission-bulk")
def map_permission_bulk(
    request: Request,
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user),
    service: AccessPointService = Depends(get_access_point_service)
):
    return service.map_permission_bulk(file, current_user['user_id'],request=request,current_user=current_user)

@router.delete("/{access_uuid}/unmap-permission/{permission_uuid}")
def unmap_permission(
    access_uuid: str,
    permission_uuid: str,
    request: Request,
    current_user: dict = Depends(get_current_user),
    service: AccessPointService = Depends(get_access_point_service)
):
    return service.unmap_permission_both(access_uuid, permission_uuid,request=request,current_user=current_user)


@router.post("{access_uuid}/map-permission")
def map_permission_new(
    access_uuid: str,
    data: PermissionMappingIn,
    request: Request,
    current_user: dict = Depends(get_current_user),
    service: AccessPointService = Depends(get_access_point_service)
):
    return service.map_permission(access_uuid, data.permission_uuid,current_user['user_id'],request=request,current_user=current_user)

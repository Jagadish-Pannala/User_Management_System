from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from typing import List

from ..interfaces.access_point import (
    AccessPointCreate,
    AccessPointUpdate,
    AccessPointOut,
    CreateAPResponse,PermissionMappingIn
)
from ...Business_Layer.services.access_point_service import AccessPointService
from ...Data_Access_Layer.utils.dependency import get_db
from ..JWT.jwt_validator.auth.dependencies import admin_required

router = APIRouter()


def get_access_point_service(db: Session = Depends(get_db)) -> AccessPointService:
    return AccessPointService(db)


@router.get("/modules", response_model=List[str])
def get_all_modules(
    _: dict = Depends(admin_required),
    service: AccessPointService = Depends(get_access_point_service)
):
    return service.list_modules()

@router.get("/unmapped-access-points", response_model=List[AccessPointOut])
def get_unmapped_access_points(
    _: dict = Depends(admin_required),
    service: AccessPointService = Depends(get_access_point_service)
):
    return service.get_unmapped_access_points()

@router.get("/unmapped-permissions")
def get_unmapped_permissions(
    _: dict = Depends(admin_required),
    service: AccessPointService = Depends(get_access_point_service)
):
    return service.get_unmapped_permissions()


@router.post("/", response_model=CreateAPResponse)
def create_ap(
    data: AccessPointCreate,
    _: dict = Depends(admin_required),
    service: AccessPointService = Depends(get_access_point_service)
):
    return service.create_access_point(data)


@router.get("/", response_model=List[AccessPointOut])
def list_aps(
    _: dict = Depends(admin_required),
    service: AccessPointService = Depends(get_access_point_service)
):
    return service.list()


@router.get("/{access_id}", response_model=AccessPointOut)
def get_ap(
    access_id: int,
    _: dict = Depends(admin_required),
    service: AccessPointService = Depends(get_access_point_service)
):
    return service.get(access_id)


@router.put("/{access_id}", response_model=AccessPointOut)
def update_ap(
    access_id: int,
    data: AccessPointUpdate,
    _: dict = Depends(admin_required),
    service: AccessPointService = Depends(get_access_point_service)
):
    return service.update(access_id, data)


@router.delete("/{access_id}")
def delete_ap(
    access_id: int,
    _: dict = Depends(admin_required),
    service: AccessPointService = Depends(get_access_point_service)
):
    return service.delete(access_id)


@router.post("/{access_id}/map-permission/{permission_id}")
def map_permission(
    access_id: int,
    permission_id: int,
    _: dict = Depends(admin_required),
    service: AccessPointService = Depends(get_access_point_service)
):
    return service.map_permission(access_id, permission_id)


@router.delete("/{access_id}/unmap-permission/{permission_id}")
def unmap_permission(
    access_id: int,
    permission_id: int,
    _: dict = Depends(admin_required),
    service: AccessPointService = Depends(get_access_point_service)
):
    return service.unmap_permission_both(access_id, permission_id)


@router.post("/access-points/{access_id}/map-permission")
def map_permission_new(
    access_id: int,
    data: PermissionMappingIn,
    _: dict = Depends(admin_required),
    service: AccessPointService = Depends(get_access_point_service)
):
    return service.map_permission(access_id, data.permission_id)

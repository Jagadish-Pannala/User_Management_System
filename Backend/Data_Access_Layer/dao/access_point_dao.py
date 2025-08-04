from sqlalchemy.orm import Session, joinedload
from sqlalchemy.exc import IntegrityError
from ..models.models import AccessPoint, AccessPointPermission, Permissions
from typing import Optional, List


class AccessPointDAO:
    def __init__(self, db: Session):
        self.db = db

    # ===================== AccessPoint =========================
    def create_access_point(self, endpoint_path: str, method: str, module: str, is_public: bool = False) -> AccessPoint:
        access_point = AccessPoint(
            endpoint_path=endpoint_path,
            method=method.upper(),
            module=module,
            is_public=is_public
        )
        self.db.add(access_point)
        self.db.commit()
        self.db.refresh(access_point)
        return access_point

    def get_access_point_by_path_and_method(self, endpoint_path: str, method: str) -> Optional[AccessPoint]:
        return self.db.query(AccessPoint).filter_by(endpoint_path=endpoint_path, method=method.upper()).first()

    def get_access_point_by_id(self, access_id: int) -> Optional[AccessPoint]:
        return self.db.query(AccessPoint).options(
            joinedload(AccessPoint.permission_mappings).joinedload(AccessPointPermission.permission)
        ).filter_by(access_id=access_id).first()


    def get_all_access_points(self) -> List[AccessPoint]:
        return (
            self.db.query(AccessPoint)
            .options(
                joinedload(AccessPoint.permission_mappings)
                .joinedload("permission")  # Join permission from AccessPointPermission
            )
            .all()
        )

    def update_access_point(self, access_id: int, **data) -> Optional[AccessPoint]:
        ap = self.db.query(AccessPoint).filter_by(access_id=access_id).first()
        if not ap:
            return None

        # 1. Update standard fields
        access_point_fields = ['endpoint_path', 'method', 'module', 'is_public']
        for field in access_point_fields:
            if field in data and getattr(ap, field) != data[field]:
                setattr(ap, field, data[field])

        # 2. Update permission_code if provided
        if 'permission_code' in data:
            new_code = data['permission_code']

            # Get mapping
            mapping = (
                self.db.query(AccessPointPermission)
                .filter_by(access_id=access_id)
                .first()
            )

            if mapping:
                permission = (
                    self.db.query(Permissions)
                    .filter_by(permission_id=mapping.permission_id)
                    .first()
                )
                if permission and permission.permission_code != new_code:
                    permission.permission_code = new_code

        self.db.commit()
        return ap

    def get_unmapped_access_points(self) -> List[AccessPoint]:
        """
        Return all access points that have no permission mappings.
        """
        return self.db.query(AccessPoint).filter(~AccessPoint.permission_mappings.any()).all()


    def get_distinct_modules(self) -> List[str]:
        result = self.db.query(AccessPoint.module).distinct().all()
        return [r[0] for r in result if r[0]]

    def delete_access_point(self, access_id: int) -> bool:
        ap = self.db.query(AccessPoint).filter_by(access_id=access_id).first()
        if not ap:
            return False
        self.db.delete(ap)
        self.db.commit()
        return True

    # ===================== Permission =========================
    def create_permission(self, permission_code: str, description: Optional[str] = None) -> Permissions:
        permission = Permissions(permission_code=permission_code, description=description)
        self.db.add(permission)
        self.db.commit()
        self.db.refresh(permission)
        return permission

    def get_permission_by_code(self, permission_code: str) -> Optional[Permissions]:
        return self.db.query(Permissions).filter_by(permission_code=permission_code).first()

    def get_permission_by_id(self, permission_id: int) -> Optional[Permissions]:
        return self.db.query(Permissions).filter_by(permission_id=permission_id).first()

    def delete_permission_if_unused(self, permission_id: int) -> bool:
        perm = self.get_permission_by_id(permission_id)
        if perm and not perm.access_mappings:
            self.db.delete(perm)
            self.db.commit()
            return True
        return False

    # ===================== AccessPointPermission Mapping =========================
    def create_access_permission_mapping(self, access_id: int, permission_id: int) -> AccessPointPermission:
        mapping = AccessPointPermission(
            access_id=access_id,
            permission_id=permission_id
        )
        self.db.add(mapping)
        self.db.commit()
        self.db.refresh(mapping)
        return mapping

    def get_mapping_by_access_id(self, access_id: int) -> Optional[AccessPointPermission]:
        return self.db.query(AccessPointPermission).filter_by(access_id=access_id).first()

    def delete_mapping_by_access_id(self, access_id: int) -> bool:
        mapping = self.get_mapping_by_access_id(access_id)
        if not mapping:
            return False
        self.db.delete(mapping)
        self.db.commit()
        return True

    def get_all_access_point_permission_ids(self) -> List[int]:
        access_points = self.db.query(AccessPoint).options(
            joinedload(AccessPoint.permission_mappings)
        ).all()

        permission_ids = []
        for ap in access_points:
            for mapping in ap.permission_mappings:
                permission_ids.append(mapping.permission_id)

        return permission_ids
    
    def unmap_permission_dao(self, access_id: int, permission_id: int) -> bool:
        mapping = (
            self.db.query(AccessPointPermission)
            .filter_by(access_id=access_id, permission_id=permission_id)
            .first()
        )
        if not mapping:
            return False
        self.db.delete(mapping)
        self.db.commit()
        return True
    
    def get_unmapped_permissions(self) -> List[Permissions]:
        return (
            self.db.query(Permissions)
            .filter(~Permissions.access_mappings.any())
            .all()
        )

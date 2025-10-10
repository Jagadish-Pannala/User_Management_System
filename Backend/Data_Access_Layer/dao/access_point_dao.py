from sqlalchemy.orm import Session, joinedload
from sqlalchemy.exc import IntegrityError
from sqlalchemy import text
from ..models.models import AccessPoint, AccessPointPermission, Permissions
from typing import Optional, List
import re
from datetime import datetime


class AccessPointDAO:
    def __init__(self, db: Session):
        self.db = db

    # ===================== AccessPoint =========================
    def create_access_point(self, endpoint_path: str,created_by: int,access_uuid:str, regex_pattern: str, method: str, module: str, is_public: bool = False,) -> AccessPoint:
        now = datetime.utcnow()
        access_point = AccessPoint(
            endpoint_path=endpoint_path,
            regex_pattern=regex_pattern,
            method=method.upper(),
            module=module,
            is_public=is_public,
            created_by=created_by,
            access_uuid=access_uuid,
            created_at=now,
            updated_at=now
        )
        self.db.add(access_point)
        self.db.commit()
        self.db.refresh(access_point)
        return access_point
    
    def get_by_endpoint_path(self, endpoint_path: str):
        return self.db.query(AccessPoint).filter_by(endpoint_path=endpoint_path).first()


    # def get_access_point_by_path_and_method(self, endpoint_path: str, method: str) -> Optional[AccessPoint]:
    #     return self.db.query(AccessPoint).filter_by(endpoint_path=endpoint_path, method=method.upper()).first()
    def get_access_point_by_path_and_method(self, endpoint_path: str, method: str) -> Optional[AccessPoint]:
        # First, try exact match
        ap = self.db.query(AccessPoint).filter_by(endpoint_path=endpoint_path, method=method.upper()).first()
        if ap:
            return ap
        
        # Then try regex match for dynamic endpoints
        aps_with_regex = self.db.query(AccessPoint).filter(
            AccessPoint.regex_pattern.isnot(None),
            AccessPoint.method == method.upper()
        ).all()
        
        for ap in aps_with_regex:
            if re.match(ap.regex_pattern, endpoint_path):
                return ap
        
        return None
    
    def get_access_point_by_id(self, access_id: int) -> Optional[AccessPoint]:
        return self.db.query(AccessPoint).options(
            joinedload(AccessPoint.permission_mappings).joinedload(AccessPointPermission.permission)
        ).filter_by(access_id=access_id).first()
    
    def get_access_point_by_uuid(self, access_uuid: str) -> Optional[AccessPoint]:
        return self.db.query(AccessPoint).options(
            joinedload(AccessPoint.permission_mappings).joinedload(AccessPointPermission.permission)
        ).filter_by(access_uuid=access_uuid).first()


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
        now = datetime.utcnow()
        data['updated_at'] = now
        ap = self.get_access_point_by_id(access_id)
        if not ap:
            return None
        print(f"🔍 DEBUG: Updating AccessPoint ID {access_id} with data: {data}")
        fields_to_update = ['endpoint_path', 'regex_pattern', 'method', 'module', 'is_public', 'updated_at']
        for field in fields_to_update:
            if field in data:
                setattr(ap, field, data[field])
        self.db.commit()
        self.db.refresh(ap)
    
    def update_access_point_permission(self, access_id: int, permission_code: Optional[str]) -> Optional[AccessPointPermission]:
        app = self.db.query(AccessPointPermission).filter_by(access_id=access_id).first()

        # --- DELETE LOGIC ---
        if permission_code in ("Null", None, "", "null"):
            if app:
                try:
                    self.db.delete(app)
                    self.db.commit()
                except Exception as e:
                    self.db.rollback()
            else:
                print(f"No mapping found for access_id={access_id}")
            return None

        # --- UPDATE / CREATE LOGIC ---
        permission = self.db.query(Permissions).filter_by(permission_code=permission_code).first()
        if not permission:
            print(f"Permission not found: {permission_code}")
            return None

        if app:
            app.permission_id = permission.permission_id
            app.assigned_at = datetime.utcnow()
        else:
            app = AccessPointPermission(
                access_id=access_id,
                permission_id=permission.permission_id,
                assigned_at=datetime.utcnow()
            )
            self.db.add(app)

        self.db.commit()
        self.db.refresh(app)
        return app

    def get_permission_code_by_access_id(self, access_id: int) -> Optional[str]:
        app = self.db.query(AccessPointPermission).filter_by(access_id=access_id).first()
        if not app:
            return None

        permission = self.db.query(Permissions).filter_by(permission_id=app.permission_id).first()
        # Ensure we return a single string, not a list or tuple
        return permission.permission_code if permission else None


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
    def create_access_permission_mapping(self, access_id: int, permission_id: int,assigned_by:int) -> AccessPointPermission:
        now = datetime.utcnow()

        mapping = AccessPointPermission(
            access_id=access_id,
            permission_id=permission_id,
            assigned_at=now,
            assigned_by=assigned_by  # You can modify this to accept an assigned_by parameter if needed
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
    def get_permissions_for_access_point(self, access_id: int) -> List[str]:
        """
        Get permission codes for a specific access point.
        """
        query = text("""
            SELECT p.permission_code 
            FROM Access_Point_Permission_Mapping appm
            JOIN Permissions p ON appm.permission_id = p.permission_id
            WHERE appm.access_id = :access_id
        """)
        
        result = self.db.execute(query, {"access_id": access_id})
        return [row[0] for row in result.fetchall()]
    
    # Add this debug method to your AccessPointDAO class

    def get_permissions_for_access_point_debug(self, access_id: int) -> List[str]:
        """
        Debug version to see what's happening with permissions query.
        """
        print(f"\n🔍 DEBUG: Getting permissions for access_id: {access_id}")
        
        try:
            # First, let's check if the access point exists
            access_point_check = self.db.execute(
                text("SELECT * FROM Access_Point WHERE access_id = :access_id"),
                {"access_id": access_id}
            ).fetchone()
            
            print(f"   Access Point exists: {access_point_check is not None}")
            if access_point_check:
                print(f"   Access Point: {dict(access_point_check)}")
            
            # Check mapping table
            mapping_query = text("""
                SELECT * FROM Access_Point_Permission_Mapping 
                WHERE access_id = :access_id
            """)
            mappings = self.db.execute(mapping_query, {"access_id": access_id}).fetchall()
            print(f"   Permission mappings found: {len(mappings)}")
            for mapping in mappings:
                print(f"     Mapping: {dict(mapping)}")
            
            # Get permissions with full query
            query = text("""
                SELECT p.permission_id, p.permission_code, p.permission_name
                FROM Access_Point_Permission_Mapping appm
                JOIN Permissions p ON appm.permission_id = p.permission_id
                WHERE appm.access_id = :access_id
            """)
            
            result = self.db.execute(query, {"access_id": access_id})
            permissions = result.fetchall()
            
            print(f"   Permissions query result: {len(permissions)} permissions found")
            permission_codes = []
            for perm in permissions:
                perm_dict = dict(perm)
                print(f"     Permission: {perm_dict}")
                permission_codes.append(perm_dict['permission_code'])
            
            print(f"   Final permission codes: {permission_codes}")
            return permission_codes
            
        except Exception as e:
            print(f"   ❌ Error in permissions query: {str(e)}")
            logger.error(f"Error getting permissions for access point {access_id}: {str(e)}")
            return []

    # Also add this method to check your database data
    def debug_database_setup(self):
        """
        Debug method to check your database setup
        """
        print("\n🔍 DEBUG: Checking database setup...")
        
        try:
            # Check Access_Point table
            access_points = self.db.execute(text("SELECT COUNT(*) as count FROM Access_Point")).fetchone()
            print(f"   Access Points in DB: {access_points['count']}")
            
            # Check Permissions table
            permissions = self.db.execute(text("SELECT COUNT(*) as count FROM Permissions")).fetchone()
            print(f"   Permissions in DB: {permissions['count']}")
            
            # Check mapping table
            mappings = self.db.execute(text("SELECT COUNT(*) as count FROM Access_Point_Permission_Mapping")).fetchone()
            print(f"   Permission Mappings in DB: {mappings['count']}")
            
            # Show sample data
            print("\n   Sample Access Points:")
            sample_aps = self.db.execute(text("SELECT * FROM Access_Point LIMIT 3")).fetchall()
            for ap in sample_aps:
                print(f"     {dict(ap)}")
                
            print("\n   Sample Permissions:")
            sample_perms = self.db.execute(text("SELECT * FROM Permissions LIMIT 5")).fetchall()
            for perm in sample_perms:
                print(f"     {dict(perm)}")
                
            print("\n   Sample Mappings:")
            sample_mappings = self.db.execute(text("""
                SELECT appm.*, ap.endpoint_path, ap.method, p.permission_code 
                FROM Access_Point_Permission_Mapping appm
                JOIN Access_Point ap ON appm.access_id = ap.access_id
                JOIN Permissions p ON appm.permission_id = p.permission_id
                LIMIT 5
            """)).fetchall()
            for mapping in sample_mappings:
                print(f"     {dict(mapping)}")
                
        except Exception as e:
            print(f"   ❌ Error checking database: {str(e)}")

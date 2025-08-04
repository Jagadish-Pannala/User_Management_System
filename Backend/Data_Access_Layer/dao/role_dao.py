from sqlalchemy.orm import Session
from ..models import models
from ...Api_Layer.interfaces.role_mangement import RoleBase

def get_all_roles(db: Session):
    return db.query(models.Role).all()

def get_role(db: Session, role_id: int):
    return db.query(models.Role).filter_by(role_id=role_id).first()

def get_role_by_name(db: Session, name: str):
    return db.query(models.Role).filter_by(role_name=name).first()

def create_role(db: Session, role: RoleBase):
    new_role = models.Role(role_name=role.role_name)
    db.add(new_role)
    db.commit()
    db.refresh(new_role)
    return new_role

def update_role(db: Session, role_id: int, role: RoleBase):
    role_db = db.query(models.Role).filter_by(role_id=role_id).first()
    if not role_db:
        raise Exception("Role not found")
    role_db.role_name = role.role_name
    db.commit()
    db.refresh(role_db)
    return role_db

def delete_role(db: Session, role_id: int):
    role = db.query(models.Role).filter_by(role_id=role_id).first()
    if not role:
        raise Exception("Role not found")
    db.delete(role)
    db.commit()
    return {"message": "Role deleted successfully"}

def update_role_groups(db: Session, role_id: int, group_ids: list[int]):
    db.query(models.Role_Permission_Group).filter_by(role_id=role_id).delete()
    for gid in group_ids:
        db.add(models.Role_Permission_Group(role_id=role_id, group_id=gid))
    db.commit()
    return {"message": "Permissions updated for role"}

def get_permissions_by_role(db: Session, role_id: int):
    role = db.query(models.Role).filter_by(role_id=role_id).first()
    if not role:
        raise Exception("Role not found")
    group_ids = db.query(models.Role_Permission_Group.group_id).filter_by(role_id=role_id).all()
    group_ids = [g[0] for g in group_ids]

    permissions = db.query(models.Permissions.permission_code, models.Permissions.description)\
        .join(models.Permission_Group_Mapping,
              models.Permissions.permission_id == models.Permission_Group_Mapping.permission_id)\
        .filter(models.Permission_Group_Mapping.group_id.in_(group_ids)).distinct().all()

    return [{"code": p[0], "description": p[1]} for p in permissions]

def get_permission_groups_by_role(db: Session, role_id: int):
    return (
        db.query(models.Permission_Group)
        .join(models.Role_Permission_Group, models.Role_Permission_Group.group_id == models.Permission_Group.group_id)
        .filter(models.Role_Permission_Group.role_id == role_id)
        .all()
    )


def add_permission_groups_to_role(db: Session, role_id: int, group_ids: list[int]):
    for gid in group_ids:
        exists = db.query(models.Role_Permission_Group)\
                   .filter_by(role_id=role_id, group_id=gid).first()
        if not exists:
            db.add(models.Role_Permission_Group(role_id=role_id, group_id=gid))
    db.commit()
    return {"message": "Permission groups added"}

def remove_permission_group_from_role(db: Session, role_id: int, group_id: int):
    db.query(models.Role_Permission_Group)\
      .filter_by(role_id=role_id, group_id=group_id).delete()
    db.commit()
    return {"message": "Permission group removed"}

# below code delete excisting groups and add new permission groups to role
# def update_permission_groups_for_role(db: Session, role_id: int, group_ids: list[int]):
#     # Delete existing groups
#     db.query(models.Role_Permission_Group).filter_by(role_id=role_id).delete()
#     # Add new ones
#     for gid in group_ids:
#         db.add(models.Role_Permission_Group(role_id=role_id, group_id=gid))
#     db.commit()
#     return {"message": "Permission groups updated"}
# below code add permission groups to excisting groups for a role
def update_permission_groups_for_role(db: Session, role_id: int, group_ids: list[int]):
    role = db.query(models.Role).filter_by(role_id=role_id).first()
    if not role:
        raise Exception("Role not found")

    # Use the correct attribute: role.permission_groups
    existing_group_ids = {group.group_id for group in role.permission_groups}

    new_group_ids = set(group_ids) - existing_group_ids
    if new_group_ids:
        new_groups = db.query(models.Permission_Group).filter(
            models.Permission_Group.group_id.in_(new_group_ids)
        ).all()
        role.permission_groups.extend(new_groups)

    db.commit()
    return {"message": "Permission groups updated successfully."}



def get_permission_groups_by_role(db: Session, role_id: int):
    return db.query(models.Permission_Group)\
             .join(models.Role_Permission_Group,
                   models.Permission_Group.group_id == models.Role_Permission_Group.group_id)\
             .filter(models.Role_Permission_Group.role_id == role_id).all()

def get_unassigned_permission_groups(db: Session, role_id: int):
    # Subquery: get group_ids already assigned to the role
    assigned_group_ids = db.query(models.Role_Permission_Group.group_id)\
                           .filter_by(role_id=role_id).subquery()
 
    # Get all permission groups NOT in the assigned list
    unassigned_groups = db.query(models.Permission_Group)\
                          .filter(~models.Permission_Group.group_id.in_(assigned_group_ids))\
                          .all()
 
    return unassigned_groups


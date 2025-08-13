from sqlalchemy.orm import Session
from sqlalchemy import exists
from ..models import models
from ...Api_Layer.interfaces.role_mangement import RoleBase
from fastapi import HTTPException


def get_all_roles(db: Session):
    return db.query(models.Role).all()


def get_role(db: Session, role_id: int):
    return db.query(models.Role).filter(models.Role.role_id == role_id).first()


def get_role_by_name(db: Session, name: str):
    return db.query(models.Role).filter(models.Role.role_name == name).first()


def create_role(db: Session, role: RoleBase):
    new_role = models.Role(role_name=role.role_name)
    db.add(new_role)
    db.commit()
    db.refresh(new_role)
    return new_role


def update_role(db: Session, role_id: int, role: RoleBase):
    role_db = get_role(db, role_id)
    if not role_db:
        raise Exception("Role not found")
    role_db.role_name = role.role_name
    db.commit()
    db.refresh(role_db)
    return role_db


def delete_role(db: Session, role_id: int):
    role = get_role(db, role_id)
    if not role:
        raise Exception("Role not found")
    db.delete(role)
    db.commit()
    return {"message": "Role deleted successfully"}


def update_role_groups(db: Session, role_id: int, group_ids: list[int]):
    db.query(models.Role_Permission_Group).filter_by(role_id=role_id).delete()
    db.bulk_save_objects([
        models.Role_Permission_Group(role_id=role_id, group_id=gid) for gid in group_ids
    ])
    db.commit()
    return {"message": "Permissions updated for role"}


def get_permissions_by_role(db: Session, role_id: int):
    if not db.query(exists().where(models.Role.role_id == role_id)).scalar():
        raise Exception("Role not found")

    group_ids = db.query(models.Role_Permission_Group.group_id)\
                  .filter_by(role_id=role_id).all()
    group_ids = [g[0] for g in group_ids]

    if not group_ids:
        return []

    permissions = (
        db.query(models.Permissions.permission_code, models.Permissions.description)
        .join(models.Permission_Group_Mapping,
              models.Permissions.permission_id == models.Permission_Group_Mapping.permission_id)
        .filter(models.Permission_Group_Mapping.group_id.in_(group_ids))
        .distinct()
        .all()
    )

    return [{"code": code, "description": desc} for code, desc in permissions]


def get_permission_groups_by_role(db: Session, role_id: int):
    return (
        db.query(models.Permission_Group)
        .join(models.Role_Permission_Group,
              models.Permission_Group.group_id == models.Role_Permission_Group.group_id)
        .filter(models.Role_Permission_Group.role_id == role_id)
        .all()
    )


def add_permission_groups_to_role(db: Session, role_id: int, group_ids: list[int]):
    group_ids = list({int(g) for g in group_ids})

    existing_group_ids = {
        gid for (gid,) in db.query(models.Permission_Group.group_id).all()
    }
    invalid_ids = [gid for gid in group_ids if gid not in existing_group_ids]
    if invalid_ids:
        raise HTTPException(
            status_code=400,
            detail=f"The following group IDs do not exist: {invalid_ids}"
        )

    new_assignments = [
        models.Role_Permission_Group(role_id=role_id, group_id=gid)
        for gid in group_ids
        if not db.query(exists().where(
            models.Role_Permission_Group.role_id == role_id,
            models.Role_Permission_Group.group_id == gid
        )).scalar()
    ]

    if new_assignments:
        db.bulk_save_objects(new_assignments)
        db.commit()

    return {"message": "Permission groups added successfully"}


def remove_permission_group_from_role(db: Session, role_id: int, group_id: int):
    group_id = int(group_id)

    if not db.query(exists().where(models.Permission_Group.group_id == group_id)).scalar():
        raise HTTPException(
            status_code=400,
            detail=f"Permission group ID {group_id} does not exist"
        )

    assignment = db.query(models.Role_Permission_Group)\
                   .filter_by(role_id=role_id, group_id=group_id)\
                   .first()
    if not assignment:
        raise HTTPException(
            status_code=400,
            detail=f"Permission group ID {group_id} is not assigned to role ID {role_id}"
        )

    db.delete(assignment)
    db.commit()
    return {"message": f"Permission group ID {group_id} removed from role ID {role_id}"}


def update_permission_groups_for_role(db: Session, role_id: int, group_ids: list[int]):
    role = get_role(db, role_id)
    if not role:
        raise Exception("Role not found")

    existing_group_ids = {group.group_id for group in role.permission_groups}
    new_group_ids = set(group_ids) - existing_group_ids

    if new_group_ids:
        new_groups = db.query(models.Permission_Group)\
                       .filter(models.Permission_Group.group_id.in_(new_group_ids))\
                       .all()
        role.permission_groups.extend(new_groups)
        db.commit()

    return {"message": "Permission groups updated successfully."}


def get_unassigned_permission_groups(db: Session, role_id: int):
    assigned_group_ids = db.query(models.Role_Permission_Group.group_id)\
                           .filter_by(role_id=role_id)\
                           .subquery()
    return db.query(models.Permission_Group)\
             .filter(~models.Permission_Group.group_id.in_(assigned_group_ids))\
             .all()

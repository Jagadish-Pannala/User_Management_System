import { useAuth } from "../../contexts/AuthContext";
import UserManagement from "./admin/userManagement/UserManagement";
import Profile from "./user/Profile";

export default function UserManagementEntry() {
  const { user } = useAuth();
  const isAdmin = user?.roles?.includes("Admin") || user?.roles?.includes("Super Admin");
  console.log(user);
  console.log("User roles:", user?.roles);
  console.log("User roles:", isAdmin);

  if (isAdmin) {
    console.log("User is an admin, rendering User Management");
    return <UserManagement />;
  }
  return <Profile />;
} 
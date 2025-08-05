import { Routes, Route } from "react-router-dom";
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

// Layout Components
import Header from "./components/Layout/Header";
import Sidebar from "./components/Layout/Sidebar";
import Layout from "./components/Layout/Layout";

// Auth Pages
import Login from "./pages/User_Management/auth/Login";
import LoginCallback from "./pages/User_Management/auth/LoginCallback";
import Register from "./pages/User_Management/auth/Register";
import ForgotPassword from "./pages/User_Management/auth/ForgotPassword";

// User Pages
import Home from "./pages/User_Management/user/Home";
import Profile from "./pages/User_Management/user/Profile";
import EditProfile from "./pages/User_Management/user/EditProfile";
import EditUserHr from "./pages/User_Management/user/manager/EditUserHr";

// Admin Pages
import AdminDashboard from "./pages/User_Management/admin/adminDashboard/AdminDashboard";
import UserManagement from "./pages/User_Management/admin/userManagement/UserManagement";
import CreateUser from "./pages/User_Management/admin/userManagement/CreateUser";
import EditUser from "./pages/User_Management/admin/userManagement/EditUser";
import UpdateUserRoles from "./pages/User_Management/admin/userManagement/UpdateUserRoles";
import EditUserRoleForm from "./pages/User_Management/admin/userManagement/EditUserRoleForm";
import RoleManagement from "./pages/User_Management/admin/roleManagement/RoleManagement";
import PermissionManagement from "./pages/User_Management/admin/permissionManagement/PermissionManagement";
import PermissionGroupManagement from "./pages/User_Management/admin/permissionGroupManagement/PermissionGroupManagement";
import AccessPointManagement from "./pages/User_Management/admin/accessPointManagement/AccessPointManagement";
import UserManagementEntry from "./pages/User_Management/UserManagementEntry";
import UsersTable from "./pages/User_Management/admin/userManagement/UsersTable";
import UserManagementHome from "./pages/User_Management/admin/userManagement/UserManagementHome";
import GroupDetails from "./pages/User_Management/admin/permissionGroupManagement/GroupDetails";
import AccessPointList from '../src/pages/User_Management/admin/accessPointManagement/AccessPointList';
import AccessPointForm from '../src/pages/User_Management/admin/accessPointManagement/AccessPointForm';
import AccessPointDetails from '../src/pages/User_Management/admin/accessPointManagement/AccessPointDetails';
import AccessPointEdit from '../src/pages/User_Management/admin/accessPointManagement/AccessPointEdit';
import AccessPointMapping from './pages/User_Management/admin/accessPointManagement/AccessPointMapping';

// Main Layout for admin/user management
import MainLayout from "./components/User_Management/MainLayout";
import AdminRoute from "./routes/User_Management/AdminRoute";

export default function App() {
  return (
    <>
      <ToastContainer position="top-center" autoClose={3000} />
      <Routes>
        {/* Public Routes */}
        <Route path="/" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/forgot" element={<ForgotPassword />} />
        {/* User & Admin Routes (with Layout) */}
        <Route element={<Layout />}>
          <Route path="/home" element={<Home />} />
          <Route path="/profile" element={<Profile />} />
          <Route path="/profile/edit" element={<EditProfile />} />
          <Route path="/edit-user/:user_id" element={<EditUserHr />} />
          <Route path="/login/callback" element={<LoginCallback />} />

          {/* User Management and Admin Sections */}
          <Route element={<MainLayout />}>
            <Route path="/user-management" element={<UserManagementEntry />}>
              <Route index element={<UserManagementHome />} />
              <Route path="users" element={<UsersTable />} />
              <Route path="users/create" element={<CreateUser />} />
              <Route path="users/edit/:id" element={<EditUser />} />
              <Route path="users/roles" element={<UpdateUserRoles />} />
              <Route path="roles" element={<RoleManagement />} />
              <Route path="roles/edit-role/:userId" element={<EditUserRoleForm />} />
              <Route path="permissions" element={<PermissionManagement />} />
              <Route path="groups" element={<PermissionGroupManagement />} />
              <Route path="groups/:groupId" element={<GroupDetails />} />
              <Route path="access-points" element={<AccessPointManagement />} />
              <Route path="access-points/create" element={<AccessPointForm />} />
              <Route path="access-points/:access_id" element={<AccessPointDetails />} />
              <Route path="access-points/edit/:access_id" element={<AccessPointEdit />} />
            </Route>
            <Route path="/admin/access-point-mapping" element={<AccessPointMapping />} />
          </Route>
        </Route>
      </Routes>
      <CreateUser />
    </>
  );
}

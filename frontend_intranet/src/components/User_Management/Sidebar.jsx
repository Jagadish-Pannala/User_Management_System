import { NavLink, useLocation } from "react-router-dom";
import {
  FaUsers,
  FaProjectDiagram,
  FaCheckCircle,
  FaClock,
  FaCalendarAlt,
  FaPlaneDeparture,
  FaChevronDown,
  FaBuilding,
} from "react-icons/fa";
import { useState } from "react";
import { useAuth } from "../../contexts/AuthContext";

const menu = [
  { label: "Dashboard", icon: <FaCheckCircle />, to: "/dashboard" },
  { label: "Projects", icon: <FaProjectDiagram />, to: "/project-management" },
  { label: "Leave Management", icon: <FaPlaneDeparture />, to: "/leave-management" },
  { label: "Timesheets", icon: <FaClock />, to: "/timesheets" },
  { label: "Calendar", icon: <FaCalendarAlt />, to: "/calendar" },
];

const userManagementSubmenu = [
  { label: "User Manage", to: "/user-management/users" },
  { label: "Role Manage", to: "/user-management/roles" },
  { label: "Permission Manage", to: "/user-management/permissions" },
  { label: "Group Manage", to: "/user-management/groups" },
  { label: "Access Point Manage", to: "/user-management/access-points" },
];

export default function Sidebar() {
  const { user } = useAuth();
  const location = useLocation();
  const [hovered, setHovered] = useState(false);

  const isAdmin = user?.roles?.includes("Admin") || user?.roles?.includes("Super Admin");

  return (
    <aside className="bg-[#0a174e] text-white w-64 min-h-screen flex flex-col">
      {/* Header */}
      <div className="flex items-center gap-4 px-6 py-6">
        <FaBuilding className="text-[#ff3d72] text-4xl" />
        <div>
          <div className="text-2xl font-bold">Paves Tech</div>
          <div className="text-sm text-gray-300">intranet</div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-4 pb-6" style={{ overflow: "visible" }}>
        <ul className="space-y-2 relative">
          {/* Admin-only User Management */}
          {isAdmin && (
            <li
              className="relative"
              onMouseEnter={() => setHovered(true)}
              onMouseLeave={() => setHovered(false)}
            >
              <div
                className={`flex items-center gap-3 px-4 py-3 rounded-lg cursor-pointer transition-colors ${
                  location.pathname.startsWith("/user-management")
                    ? "bg-[#263383] text-white"
                    : "text-gray-300 hover:bg-[#0f1536] hover:text-white"
                }`}
              >
                <FaUsers className="text-xl" />
                <span className="flex-1 font-medium">User Management</span>
                <FaChevronDown
                  className={`transition-transform duration-200 ${hovered ? "rotate-180" : ""}`}
                />
              </div>

              {hovered && (
                <ul className="absolute top-0 left-full ml-2 w-56 bg-[#0f1536] text-white rounded-lg shadow-lg z-50 py-2">
                  {userManagementSubmenu.map((item) => (
                    <li key={item.label}>
                      <NavLink
                        to={item.to}
                        className={({ isActive }) =>
                          `block px-4 py-2 rounded-md transition-colors ${
                            isActive
                              ? "bg-[#263383] text-white"
                              : "text-gray-300 hover:bg-[#263383] hover:text-white"
                          }`
                        }
                      >
                        {item.label}
                      </NavLink>
                    </li>
                  ))}
                </ul>
              )}
            </li>
          )}

          {/* Standard Menu Items */}
          {menu.map((item) => (
            <li key={item.label}>
              <NavLink
                to={item.to}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                    isActive
                      ? "bg-[#263383] text-white"
                      : "text-gray-300 hover:bg-[#0f1536] hover:text-white"
                  }`
                }
              >
                <span className="text-xl">{item.icon}</span>
                <span className="font-medium">{item.label}</span>
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>
    </aside>
  );
}

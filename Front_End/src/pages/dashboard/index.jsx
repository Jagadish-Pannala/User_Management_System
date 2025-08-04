import { FaUsers, FaProjectDiagram, FaCheckCircle, FaClock, FaCalendarAlt, FaUserCog, FaPlaneDeparture } from "react-icons/fa";

const summary = [
  { label: "Total Employees", value: 245, icon: <FaUsers />, change: "+12", changeColor: "text-green-600" },
  { label: "Active Projects", value: 12, icon: <FaProjectDiagram />, change: "+2", changeColor: "text-green-600" },
  { label: "Pending Approvals", value: 8, icon: <FaClock />, change: "-3", changeColor: "text-red-500" },
  { label: "Completed Tasks", value: "89%", icon: <FaCheckCircle />, change: "+5%", changeColor: "text-green-600" },
];

const quickAccess = [
  { label: "User Management", desc: "Manage employees, roles, and permissions", icon: <FaUserCog />, link: "/user-management", stat: "245 active users" },
  { label: "Project Management", desc: "Track projects, deadlines, and team progress", icon: <FaProjectDiagram />, link: "/project-management", stat: "12 active projects" },
  { label: "Leave Management", desc: "Handle leave requests and approvals", icon: <FaPlaneDeparture />, link: "/leave-management" },
  { label: "Timesheets", desc: "Track time and generate reports", icon: <FaClock />, link: "/timesheets" },
];

const recentActivity = [
  { title: "New user registration", user: "Sarah Johnson", time: "2 hours ago" },
  { title: "Project deadline updated", user: "Mike Chen", time: "4 hours ago" },
  { title: "Leave request approved", user: "Emily Davis", time: "6 hours ago" },
];

export default function Dashboard() {
  return (
    <div className="p-8">
      <h1 className="text-3xl font-bold mb-2">Welcome back, John</h1>
      <p className="mb-6 text-gray-500">Here's what's happening with your organization today.</p>
      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        {summary.map((item) => (
          <div key={item.label} className="bg-white rounded-xl shadow p-6 flex flex-col items-center">
            <div className="text-3xl mb-2">{item.icon}</div>
            <div className="text-2xl font-bold">{item.value}</div>
            <div className="text-gray-500">{item.label}</div>
            <div className={`${item.changeColor} text-sm`}>{item.change}</div>
          </div>
        ))}
      </div>
      {/* Quick Access & Recent Activity */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="md:col-span-2">
          <h2 className="text-xl font-semibold mb-4">Quick Access</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {quickAccess.map((item) => (
              <a href={item.link} key={item.label} className="bg-white rounded-xl shadow p-5 flex flex-col hover:bg-blue-50 transition">
                <div className="text-2xl mb-2">{item.icon}</div>
                <div className="font-bold">{item.label}</div>
                <div className="text-gray-500">{item.desc}</div>
                {item.stat && <div className="text-blue-600 text-sm mt-2">{item.stat}</div>}
              </a>
            ))}
          </div>
        </div>
        <div>
          <h2 className="text-xl font-semibold mb-4">Recent Activity</h2>
          <div className="bg-white rounded-xl shadow p-5">
            {recentActivity.map((item, idx) => (
              <div key={idx} className="mb-4 last:mb-0">
                <div className="font-medium">{item.title}</div>
                <div className="text-gray-500 text-sm">by {item.user} • {item.time}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
} 
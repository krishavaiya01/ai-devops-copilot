import React, { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { alertsService } from '../services/api';
import { 
  LayoutDashboard, 
  Terminal, 
  AlertTriangle, 
  DollarSign, 
  MessageSquare, 
  Settings as SettingsIcon, 
  LogOut, 
  Shield, 
  Bell, 
  Activity 
} from 'lucide-react';

interface LayoutProps {
  children: React.ReactNode;
  activePage: string;
  setActivePage: (page: string) => void;
}

export const Layout: React.FC<LayoutProps> = ({ children, activePage, setActivePage }) => {
  const { user, logout } = useAuth();
  const [activeAlertCount, setActiveAlertCount] = useState<number>(0);

  useEffect(() => {
    const fetchAlertCount = async () => {
      try {
        const alerts = await alertsService.getAlerts();
        const activeAlerts = alerts.filter((a: any) => a.status === 'active');
        setActiveAlertCount(activeAlerts.length);
      } catch (err) {
        console.error("Failed to load active alerts count:", err);
      }
    };
    fetchAlertCount();
    const interval = setInterval(fetchAlertCount, 15000); // refresh every 15s
    return () => clearInterval(interval);
  }, []);

  const navItems = [
    { id: 'dashboard', name: 'Dashboard', icon: LayoutDashboard },
    { id: 'analyzer', name: 'Log Analyzer', icon: Terminal },
    { id: 'incidents', name: 'Incident Center', icon: AlertTriangle },
    { id: 'cost', name: 'Cost Optimization', icon: DollarSign },
    { id: 'chat', name: 'AI Chat', icon: MessageSquare },
    { id: 'settings', name: 'Settings', icon: SettingsIcon },
  ];

  return (
    <div className="flex h-screen bg-[#090d16] text-gray-100 overflow-hidden font-sans">
      {/* Sidebar */}
      <aside className="w-64 bg-[#0d1424] border-r border-[#1e293b] flex flex-col justify-between shrink-0">
        <div>
          {/* Logo / Header */}
          <div className="p-6 border-b border-[#1e293b] flex items-center space-x-3">
            <Activity className="h-6 w-6 text-indigo-400 animate-pulse" />
            <span className="text-lg font-bold tracking-tight text-white">DevOps Copilot</span>
          </div>

          {/* Navigation Links */}
          <nav className="p-4 space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activePage === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActivePage(item.id)}
                  className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-sm font-medium transition-all ${
                    isActive
                      ? 'bg-indigo-600/20 text-indigo-300 border-l-4 border-indigo-500'
                      : 'text-gray-400 hover:bg-[#162238] hover:text-gray-200'
                  }`}
                >
                  <Icon className={`h-5 w-5 ${isActive ? 'text-indigo-400' : 'text-gray-400'}`} />
                  <span>{item.name}</span>
                  {item.id === 'incidents' && activeAlertCount > 0 && (
                    <span className="ml-auto bg-rose-500 text-white text-xs px-2 py-0.5 rounded-full animate-bounce">
                      {activeAlertCount}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* User Info & Footer */}
        <div className="p-4 border-t border-[#1e293b] bg-[#0a101d]">
          <div className="flex items-center space-x-3 mb-4">
            <div className="h-10 w-10 rounded-full bg-indigo-500/20 border border-indigo-500/30 flex items-center justify-center text-indigo-400 font-bold uppercase">
              {user?.username?.charAt(0) || 'U'}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-semibold text-white truncate">{user?.username || 'Guest'}</p>
              <div className="flex items-center space-x-1 mt-0.5 text-xs text-gray-400">
                <Shield className="h-3 w-3 text-emerald-400" />
                <span className="capitalize">{user?.role || 'viewer'}</span>
              </div>
            </div>
          </div>
          
          <button
            onClick={logout}
            className="w-full flex items-center justify-center space-x-2 bg-rose-950/20 text-rose-400 border border-rose-900/30 py-2 rounded-lg hover:bg-rose-950/40 transition-colors text-xs font-semibold"
          >
            <LogOut className="h-4 w-4" />
            <span>Sign Out</span>
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Navbar */}
        <header className="h-16 bg-[#0d1424] border-b border-[#1e293b] flex items-center justify-between px-8 shrink-0">
          <h2 className="text-xl font-bold text-white capitalize">
            {navItems.find(n => n.id === activePage)?.name || activePage}
          </h2>

          <div className="flex items-center space-x-6">
            {/* Status Indicator */}
            <div className="flex items-center space-x-2 bg-[#162238] px-3 py-1.5 rounded-full border border-emerald-500/20 text-xs">
              <span className="h-2 w-2 rounded-full bg-emerald-500 animate-ping"></span>
              <span className="text-gray-300 font-medium">All systems operational</span>
            </div>

            {/* Notification bell */}
            <div className="relative cursor-pointer text-gray-400 hover:text-white">
              <Bell className="h-5 w-5" />
              {activeAlertCount > 0 && (
                <span className="absolute -top-1 -right-1 bg-rose-500 text-[10px] text-white h-4 w-4 rounded-full flex items-center justify-center font-bold">
                  {activeAlertCount}
                </span>
              )}
            </div>
          </div>
        </header>

        {/* Dynamic page content container */}
        <main className="flex-1 overflow-y-auto p-8 bg-[#090d16]">
          {children}
        </main>
      </div>
    </div>
  );
};

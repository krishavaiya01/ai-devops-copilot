import React, { useState } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Layout } from './components/Layout';
import { Login } from './pages/Login';
import { Dashboard } from './pages/Dashboard';
import { LogAnalyzer } from './pages/LogAnalyzer';
import { IncidentCenter } from './pages/IncidentCenter';
import { CostOptimization } from './pages/CostOptimization';
import { AIChat } from './pages/AIChat';
import { Settings } from './pages/Settings';
import './App.css';

const AppContent: React.FC = () => {
  const { isAuthenticated, loading } = useAuth();
  const [activePage, setActivePage] = useState<string>('dashboard');

  if (loading) {
    return (
      <div className="min-h-screen bg-[#090d16] flex flex-col items-center justify-center space-y-4">
        <div className="h-12 w-12 border-4 border-indigo-500 border-t-transparent rounded-full animate-spin"></div>
        <h2 className="text-white text-sm font-semibold tracking-wide">Loading DevOps Copilot...</h2>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Login />;
  }

  const renderPage = () => {
    switch (activePage) {
      case 'dashboard':
        return <Dashboard />;
      case 'analyzer':
        return <LogAnalyzer />;
      case 'incidents':
        return <IncidentCenter />;
      case 'cost':
        return <CostOptimization />;
      case 'chat':
        return <AIChat />;
      case 'settings':
        return <Settings />;
      default:
        return <Dashboard />;
    }
  };

  return (
    <Layout activePage={activePage} setActivePage={setActivePage}>
      {renderPage()}
    </Layout>
  );
};

function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}

export default App;

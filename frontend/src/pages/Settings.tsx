import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { User, Shield, Key, Sliders, Database, RefreshCw } from 'lucide-react';

export const Settings: React.FC = () => {
  const { user } = useAuth();
  
  // Custom API configuration toggles for demo
  const [mockMode, setMockMode] = useState<boolean>(true);
  const [region, setRegion] = useState<string>('us-east-1');
  const [keyInput, setKeyInput] = useState<string>('••••••••••••••••••••••••••••');
  const [scanned, setScanned] = useState<boolean>(false);
  const [scanning, setScanning] = useState<boolean>(false);

  const handleTestScan = () => {
    setScanning(true);
    setTimeout(() => {
      setScanning(false);
      setScanned(true);
    }, 1500);
  };

  return (
    <div className="max-w-4xl space-y-8">
      <p className="text-xs text-gray-400">Configure global configurations, cluster locations, and AI provider authorization keys.</p>

      {/* User profile segment */}
      <div className="bg-[#0d1424] border border-[#1e293b] rounded-xl p-6 space-y-6">
        <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center space-x-2 border-b border-[#1e293b] pb-4">
          <User className="h-4 w-4 text-indigo-400" />
          <span>Operator Profile Details</span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs">
          <div>
            <label className="block text-gray-400 mb-1.5 font-medium">Username</label>
            <input
              type="text"
              readOnly
              value={user?.username || ''}
              className="w-full bg-[#0a101d] border border-[#1e293b] rounded-lg px-4 py-2.5 text-gray-400 focus:outline-none cursor-not-allowed"
            />
          </div>

          <div>
            <label className="block text-gray-400 mb-1.5 font-medium">Email Address</label>
            <input
              type="email"
              readOnly
              value={user?.email || ''}
              className="w-full bg-[#0a101d] border border-[#1e293b] rounded-lg px-4 py-2.5 text-gray-400 focus:outline-none cursor-not-allowed"
            />
          </div>

          <div>
            <label className="block text-gray-400 mb-1.5 font-medium">Role Access Level</label>
            <div className="w-full bg-[#0a101d] border border-[#1e293b] rounded-lg px-4 py-2.5 text-gray-400 flex items-center space-x-2 select-none">
              <Shield className="h-4 w-4 text-emerald-400" />
              <span className="capitalize font-semibold text-white">{user?.role}</span>
            </div>
          </div>
        </div>
      </div>

      {/* AI Key & Integration Config */}
      <div className="bg-[#0d1424] border border-[#1e293b] rounded-xl p-6 space-y-6">
        <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center space-x-2 border-b border-[#1e293b] pb-4">
          <Key className="h-4 w-4 text-indigo-400" />
          <span>AI Engine Configuration</span>
        </h3>

        <div className="space-y-4 text-xs">
          <div>
            <label className="block text-gray-400 mb-1.5 font-medium">Gemini Authorization Key</label>
            <div className="relative">
              <input
                type="password"
                value={keyInput}
                onChange={(e) => setKeyInput(e.target.value)}
                placeholder="Paste GEMINI_API_KEY"
                className="w-full bg-[#070b13] border border-[#1e293b] rounded-lg px-4 py-2.5 text-gray-200 placeholder-gray-600 focus:outline-none focus:border-indigo-500"
              />
            </div>
            <span className="text-[10px] text-gray-500 block mt-1.5">
              By default, backend pulls key from `.env` file environment variables.
            </span>
          </div>

          {/* Fallback diagnostic toggle */}
          <div className="flex items-center justify-between p-4 rounded-lg bg-[#0a101d] border border-[#1e293b]/60">
            <div>
              <span className="font-semibold text-white block mb-0.5">AI Engine Hybrid Demo Fallback</span>
              <span className="text-[10px] text-gray-500 block">
                Automatically fallback to local database log dictionary if API fails or key is missing.
              </span>
            </div>
            
            <button
              onClick={() => setMockMode(!mockMode)}
              className={`w-12 h-6.5 rounded-full p-1 transition-colors duration-200 shrink-0 ${
                mockMode ? 'bg-indigo-600' : 'bg-gray-800'
              }`}
            >
              <div className={`h-4.5 w-4.5 rounded-full bg-white transition-transform duration-200 ${
                mockMode ? 'transform translate-x-5' : ''
              }`}></div>
            </button>
          </div>
        </div>
      </div>

      {/* Cluster Details */}
      <div className="bg-[#0d1424] border border-[#1e293b] rounded-xl p-6 space-y-6">
        <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center space-x-2 border-b border-[#1e293b] pb-4">
          <Sliders className="h-4 w-4 text-indigo-400" />
          <span>Telemetry Scrape Configurations</span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs">
          <div>
            <label className="block text-gray-400 mb-1.5 font-medium">Primary Cloud Target region</label>
            <select
              value={region}
              onChange={(e) => setRegion(e.target.value)}
              className="w-full bg-[#0a101d] border border-[#1e293b] rounded-lg px-4 py-2.5 text-gray-300 focus:outline-none focus:border-indigo-500 cursor-pointer"
            >
              <option value="us-east-1">us-east-1 (N. Virginia)</option>
              <option value="us-west-2">us-west-2 (Oregon)</option>
              <option value="eu-central-1">eu-central-1 (Frankfurt)</option>
              <option value="ap-south-1">ap-south-1 (Mumbai)</option>
            </select>
          </div>

          <div>
            <label className="block text-gray-400 mb-1.5 font-medium">Scrape Target Registry</label>
            <div className="w-full bg-[#0a101d] border border-[#1e293b] rounded-lg px-4 py-2.5 text-gray-400 flex items-center space-x-2 select-none">
              <Database className="h-4 w-4 text-indigo-400" />
              <span className="text-gray-300 font-medium">http://prometheus:9090</span>
            </div>
          </div>
        </div>

        {/* Scan Actions */}
        <div className="pt-4 border-t border-[#1e293b] flex items-center justify-between">
          <span className="text-[10px] text-gray-400">
            {scanned ? "Last active scan succeeded: Just now" : "Deploy cloud agent scripts to trigger dynamic scrapes."}
          </span>

          <button
            onClick={handleTestScan}
            disabled={scanning}
            className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-semibold px-4 py-2 rounded-lg flex items-center space-x-2 transition-all shadow-md shadow-indigo-600/10"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${scanning ? 'animate-spin' : ''}`} />
            <span>{scanning ? "Syncing Clusters..." : "Scan Clusters Now"}</span>
          </button>
        </div>
      </div>
    </div>
  );
};

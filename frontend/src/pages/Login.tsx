import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { Shield, Lock, Mail, User as UserIcon, Activity, ArrowRight } from 'lucide-react';

export const Login: React.FC = () => {
  const { login, signup } = useAuth();
  const [isLogin, setIsLogin] = useState<boolean>(true);
  const [username, setUsername] = useState<string>('');
  const [email, setEmail] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [role, setRole] = useState<string>('engineer');
  const [error, setError] = useState<string>('');
  const [success, setSuccess] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setLoading(true);

    try {
      if (isLogin) {
        await login(username, password);
      } else {
        await signup({ username, email, password, role });
        setSuccess('Signup successful! Please log in.');
        setIsLogin(true);
        setPassword('');
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Authentication operation failed. Please check inputs.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#090d16] relative overflow-hidden px-4">
      {/* Decorative blurred backgrounds */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-indigo-900/20 rounded-full blur-[100px] animate-pulse-slow"></div>
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-cyan-900/10 rounded-full blur-[120px] animate-pulse-slow"></div>

      <div className="w-full max-w-md glass rounded-2xl p-8 shadow-2xl relative z-10 border border-[#1e293b]/50">
        {/* Brand header */}
        <div className="flex flex-col items-center mb-8">
          <div className="h-12 w-12 rounded-xl bg-indigo-600/20 border border-indigo-500/30 flex items-center justify-center text-indigo-400 mb-3">
            <Activity className="h-6 w-6 animate-pulse" />
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight">AI DevOps Copilot</h1>
          <p className="text-gray-400 text-xs mt-1">Production SRE Incident & Control Board</p>
        </div>

        {error && (
          <div className="mb-4 bg-rose-950/30 border border-rose-900/50 text-rose-400 text-xs px-4 py-3 rounded-lg flex items-center space-x-2">
            <span>⚠️</span>
            <span>{error}</span>
          </div>
        )}

        {success && (
          <div className="mb-4 bg-emerald-950/30 border border-emerald-900/50 text-emerald-400 text-xs px-4 py-3 rounded-lg flex items-center space-x-2">
            <span>✅</span>
            <span>{success}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Username</label>
            <div className="relative">
              <UserIcon className="absolute left-3 top-3.5 h-4 w-4 text-gray-500" />
              <input
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="e.g. admin"
                className="w-full bg-[#0d1424] border border-[#1e293b] rounded-lg py-2.5 pl-10 pr-4 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
              />
            </div>
          </div>

          {!isLogin && (
            <div>
              <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Email Address</label>
              <div className="relative">
                <Mail className="absolute left-3 top-3.5 h-4 w-4 text-gray-500" />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="e.g. engineer@copilot.io"
                  className="w-full bg-[#0d1424] border border-[#1e293b] rounded-lg py-2.5 pl-10 pr-4 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
                />
              </div>
            </div>
          )}

          <div>
            <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Password</label>
            <div className="relative">
              <Lock className="absolute left-3 top-3.5 h-4 w-4 text-gray-500" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full bg-[#0d1424] border border-[#1e293b] rounded-lg py-2.5 pl-10 pr-4 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
              />
            </div>
          </div>

          {!isLogin && (
            <div>
              <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Platform Role</label>
              <div className="relative">
                <Shield className="absolute left-3 top-3.5 h-4 w-4 text-gray-500" />
                <select
                  value={role}
                  onChange={(e) => setRole(e.target.value)}
                  className="w-full bg-[#0d1424] border border-[#1e293b] rounded-lg py-2.5 pl-10 pr-4 text-sm text-gray-100 focus:outline-none focus:border-indigo-500 transition-all appearance-none cursor-pointer"
                >
                  <option value="admin">Admin (Full Control)</option>
                  <option value="engineer">Engineer (Write / Troubleshoot)</option>
                  <option value="viewer">Viewer (Read Only)</option>
                </select>
              </div>
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-medium py-2.5 rounded-lg text-sm flex items-center justify-center space-x-2 transition-all mt-6 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <span>{loading ? 'Processing...' : isLogin ? 'Sign In' : 'Create Account'}</span>
            <ArrowRight className="h-4 w-4" />
          </button>
        </form>

        <div className="mt-6 text-center">
          <button
            onClick={() => {
              setIsLogin(!isLogin);
              setError('');
            }}
            className="text-xs text-indigo-400 hover:text-indigo-300 font-medium transition-colors"
          >
            {isLogin ? "Don't have an account? Sign Up" : "Already have an account? Sign In"}
          </button>
        </div>

        {/* Demo profiles help card */}
        {isLogin && (
          <div className="mt-8 pt-6 border-t border-[#1e293b]/50 text-left">
            <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-2">Recruiter Quick Access Logs</p>
            <div className="grid grid-cols-2 gap-2 text-[11px] text-gray-400">
              <div className="bg-[#0b101c] p-2 rounded border border-[#1e293b]/30">
                <span className="font-semibold text-white block">SRE Engineer:</span>
                Username: <code className="text-indigo-300">engineer</code><br/>
                Password: <code className="text-indigo-300">engineer123</code>
              </div>
              <div className="bg-[#0b101c] p-2 rounded border border-[#1e293b]/30">
                <span className="font-semibold text-white block">Cluster Admin:</span>
                Username: <code className="text-indigo-300">admin</code><br/>
                Password: <code className="text-indigo-300">admin123</code>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

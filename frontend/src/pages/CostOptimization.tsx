import React, { useEffect, useState } from 'react';
import { costService } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend } from 'recharts';
import { DollarSign, Check, ArrowRight, ShieldAlert } from 'lucide-react';

interface Recommendation {
  id: number;
  category: string;
  description: string;
  potential_savings: number;
  status: string;
  created_at: string;
}

interface Resource {
  id: number;
  provider: string;
  resource_type: string;
  resource_id: string;
  cost_per_hour: number;
  state: string;
}

export const CostOptimization: React.FC = () => {
  const { user } = useAuth();
  const [recommendations, setRecommendations] = useState<Recommendation[]>([]);
  const [resources, setResources] = useState<Resource[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string>('');

  const fetchCostData = async () => {
    try {
      const recs = await costService.getRecommendations();
      const resList = await costService.getResources();
      setRecommendations(recs);
      setResources(resList);
      setError('');
    } catch (err) {
      console.error(err);
      setError("Failed to fetch AWS cloud usage data.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCostData();
  }, []);

  const handleApplyRecommendation = async (id: number) => {
    if (user?.role === 'viewer') return;
    try {
      await costService.updateRecommendation(id, 'applied');
      fetchCostData();
    } catch (err) {
      console.error(err);
      alert("Failed to apply recommendation optimization.");
    }
  };

  // Compute metrics
  const activeRecommendations = recommendations.filter((r) => r.status === 'pending');
  const appliedRecommendations = recommendations.filter((r) => r.status === 'applied');
  
  const totalPotentialSavings = activeRecommendations.reduce((acc, r) => acc + r.potential_savings, 0);
  const appliedSavings = appliedRecommendations.reduce((acc, r) => acc + r.potential_savings, 0);

  // Chart data: current vs optimized
  const currentMonthlySpend = 2450.00; // Mock base spend
  const optimizedMonthlySpend = currentMonthlySpend - totalPotentialSavings;

  const spendChartData = [
    {
      name: 'Monthly Cost (USD)',
      'Current Spend': currentMonthlySpend,
      'Projected Spend': optimizedMonthlySpend,
    }
  ];

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-[50vh] space-y-4">
        <div className="h-10 w-10 border-4 border-indigo-500 border-t-transparent rounded-full animate-spin"></div>
        <p className="text-gray-400 text-sm">Scanning AWS cloud bills...</p>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {error && (
        <div className="bg-rose-950/30 border border-rose-900/50 text-rose-400 text-xs px-4 py-3 rounded-lg">
          {error}
        </div>
      )}

      {/* Cloud cost summary tiles */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Total monthly savings */}
        <div className="bg-[#0d1424] border border-[#1e293b] p-6 rounded-xl flex items-center justify-between">
          <div>
            <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider block mb-1">Untapped Potential Savings</span>
            <span className="text-3xl font-extrabold text-indigo-400">${totalPotentialSavings.toFixed(2)}</span>
            <span className="text-[10px] text-gray-500 block mt-1.5">/ month optimization capacity</span>
          </div>
          <div className="h-12 w-12 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
            <DollarSign className="h-6 w-6" />
          </div>
        </div>

        {/* Applied savings */}
        <div className="bg-[#0d1424] border border-[#1e293b] p-6 rounded-xl flex items-center justify-between">
          <div>
            <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider block mb-1">Optimizations Applied</span>
            <span className="text-3xl font-extrabold text-emerald-400">${appliedSavings.toFixed(2)}</span>
            <span className="text-[10px] text-gray-500 block mt-1.5">/ month saved in billing cycle</span>
          </div>
          <div className="h-12 w-12 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <Check className="h-6 w-6" />
          </div>
        </div>

        {/* Scan Status */}
        <div className="bg-[#0d1424] border border-[#1e293b] p-6 rounded-xl flex items-center justify-between">
          <div>
            <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider block mb-1">Idle/Unused Resources</span>
            <span className="text-3xl font-extrabold text-amber-500">
              {resources.filter(r => r.state === 'idle' || r.state === 'unused').length}
            </span>
            <span className="text-[10px] text-gray-500 block mt-1.5">Detected on AWS us-east-1 region</span>
          </div>
          <div className="h-12 w-12 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-500">
            <ShieldAlert className="h-6 w-6" />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Cost Optimization Recommendations List */}
        <div className="lg:col-span-2 space-y-6">
          <h3 className="text-xs font-bold text-gray-400 uppercase tracking-widest">Active Cost Optimization Alerts</h3>

          <div className="space-y-4">
            {activeRecommendations.length === 0 ? (
              <div className="text-center py-12 text-gray-500 text-xs bg-[#0d1424] border border-[#1e293b] rounded-xl">
                🚀 Dynamic cloud architecture matches target efficiency! No active saving alerts.
              </div>
            ) : (
              activeRecommendations.map((rec) => (
                <div key={rec.id} className="bg-[#0d1424] border border-[#1e293b] rounded-xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:border-[#1e293b]/90 transition-all">
                  <div className="space-y-2 flex-1">
                    <div className="flex items-center space-x-2">
                      <span className="bg-[#162238] border border-[#1e293b] text-[9px] font-extrabold text-indigo-400 px-2 py-0.5 rounded uppercase tracking-wider">
                        {rec.category} recommendation
                      </span>
                      <span className="text-xs text-emerald-400 font-semibold">
                        Saves ${rec.potential_savings.toFixed(2)}/mo
                      </span>
                    </div>
                    <p className="text-xs font-medium text-gray-200 leading-relaxed">{rec.description}</p>
                  </div>

                  {user?.role !== 'viewer' && (
                    <button
                      onClick={() => handleApplyRecommendation(rec.id)}
                      className="bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold py-2 px-4 rounded-lg flex items-center space-x-1.5 transition-colors shrink-0 self-start md:self-auto"
                    >
                      <span>Apply Fix</span>
                      <ArrowRight className="h-3.5 w-3.5" />
                    </button>
                  )}
                </div>
              ))
            )}
          </div>

          {/* Historical applied optimizations */}
          {appliedRecommendations.length > 0 && (
            <div className="space-y-3 pt-4">
              <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Resolved Recommendations</h4>
              <div className="space-y-2.5">
                {appliedRecommendations.map((rec) => (
                  <div key={rec.id} className="bg-[#0b101c] border border-emerald-950/40 rounded-xl p-4 flex items-center justify-between text-xs text-gray-400">
                    <p className="line-clamp-1">{rec.description}</p>
                    <span className="text-emerald-500 font-semibold flex items-center space-x-1 shrink-0 ml-4">
                      <Check className="h-4 w-4" />
                      <span>Applied (+${rec.potential_savings.toFixed(2)})</span>
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Spend Chart & Resource Audits */}
        <div className="space-y-8">
          {/* Monthly spend delta */}
          <div className="bg-[#0d1424] border border-[#1e293b] p-6 rounded-xl">
            <h3 className="text-xs font-bold text-gray-400 uppercase tracking-widest mb-6">Spend Projection Matrix</h3>
            
            <div className="h-56 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={spendChartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid stroke="#1f2937" vertical={false} />
                  <XAxis dataKey="name" stroke="#6b7280" fontSize={10} />
                  <YAxis stroke="#6b7280" fontSize={10} />
                  <Tooltip cursor={{ fill: 'transparent' }} contentStyle={{ backgroundColor: '#111827', borderColor: '#1f2937', color: '#fff', fontSize: '11px' }} />
                  <Legend wrapperStyle={{ fontSize: '10px' }} />
                  <Bar dataKey="Current Spend" fill="#6366f1" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="Projected Spend" fill="#10b981" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Cloud resource inventory list */}
          <div className="bg-[#0d1424] border border-[#1e293b] p-6 rounded-xl">
            <h3 className="text-xs font-bold text-gray-400 uppercase tracking-widest mb-4">AWS Resource Scans</h3>

            <div className="space-y-3.5">
              {resources.map((res) => (
                <div key={res.id} className="flex items-center justify-between text-xs border-b border-[#1e293b]/60 pb-3 last:border-0 last:pb-0">
                  <div>
                    <span className="font-mono text-[10px] font-bold text-white block">{res.resource_id}</span>
                    <span className="text-[10px] text-gray-500 capitalize">{res.resource_type} • {res.provider}</span>
                  </div>
                  
                  <div className="text-right">
                    <span className={`px-2 py-0.5 rounded text-[9px] font-semibold border capitalize inline-block mb-1 ${
                      res.state === 'idle' || res.state === 'unused'
                        ? 'bg-amber-950/40 text-amber-400 border-amber-900/30'
                        : 'bg-emerald-950/40 text-emerald-400 border-emerald-900/30'
                    }`}>
                      {res.state}
                    </span>
                    <span className="text-[10px] text-gray-400 block">${(res.cost_per_hour * 24 * 30).toFixed(0)}/mo</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

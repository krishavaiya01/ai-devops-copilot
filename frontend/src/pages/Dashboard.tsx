import React, { useEffect, useState } from 'react';
import { metricsService, alertsService, incidentsService } from '../services/api';
import { 
  ResponsiveContainer, 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip 
} from 'recharts';
import { 
  Cpu, 
  HardDrive, 
  Activity, 
  Zap, 
  AlertOctagon, 
  Clock, 
  CheckCircle, 
  AlertTriangle 
} from 'lucide-react';

interface MetricSeries {
  time: string;
  cpu: number;
  memory: number;
  networkIn: number;
  networkOut: number;
  latency: number;
  errorRate: number;
}

interface DashboardMetrics {
  cpu: number;
  memory: number;
  networkIn: number;
  networkOut: number;
  latency: number;
  errorRate: number;
}

export const Dashboard: React.FC = () => {
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [series, setSeries] = useState<MetricSeries[]>([]);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [incidents, setIncidents] = useState<any[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string>('');

  const fetchDashboardData = async () => {
    try {
      // 1. Fetch live metrics
      const metricsData = await metricsService.getDashboardMetrics();
      setMetrics(metricsData.current);
      setSeries(metricsData.series);

      // 2. Fetch active alerts
      const alertsData = await alertsService.getAlerts();
      setAlerts(alertsData.slice(0, 5)); // Limit to top 5

      // 3. Fetch active incidents
      const incidentsData = await incidentsService.getIncidents();
      setIncidents(incidentsData.slice(0, 3)); // Limit to top 3

      setError('');
    } catch (err: any) {
      console.error("Dashboard pull failed", err);
      setError("Failed to fetch dashboard telemetry feeds.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 10000); // Poll every 10 seconds
    return () => clearInterval(interval);
  }, []);

  const handleAcknowledgeAlert = async (id: number) => {
    try {
      await alertsService.updateAlert(id, 'acknowledged');
      fetchDashboardData();
    } catch (err) {
      console.error("Failed to acknowledge alert", err);
    }
  };

  const handleResolveAlert = async (id: number) => {
    try {
      await alertsService.updateAlert(id, 'resolved');
      fetchDashboardData();
    } catch (err) {
      console.error("Failed to resolve alert", err);
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-[60vh] space-y-4">
        <div className="h-10 w-10 border-4 border-indigo-500 border-t-transparent rounded-full animate-spin"></div>
        <p className="text-gray-400 text-sm">Streaming cloud cluster metrics...</p>
      </div>
    );
  }

  // Custom tooltips for Recharts
  const ChartTooltip = ({ active, payload, label, unit }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-[#111827] border border-[#1f2937] p-3 rounded-lg text-xs shadow-lg">
          <p className="text-gray-400 mb-1">Time: {label}</p>
          <p className="text-white font-semibold">{payload[0].name}: {payload[0].value}{unit}</p>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="space-y-8">
      {error && (
        <div className="bg-rose-950/30 border border-rose-900/50 text-rose-400 text-xs px-4 py-3 rounded-lg">
          {error}
        </div>
      )}

      {/* Grafana-style Stat Cards */}
      {metrics && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6">
          {/* CPU Usage Card */}
          <div className="bg-[#0d1424] border border-[#1e293b] p-6 rounded-xl relative overflow-hidden">
            <div className="flex items-center justify-between mb-4">
              <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">CPU Utilization</span>
              <Cpu className="h-5 w-5 text-indigo-400" />
            </div>
            <div className="flex items-baseline space-x-2">
              <span className="text-3xl font-extrabold text-white">{metrics.cpu}%</span>
            </div>
            <div className="mt-3 w-full bg-[#162238] rounded-full h-1.5 overflow-hidden">
              <div 
                className={`h-full rounded-full ${metrics.cpu > 80 ? 'bg-rose-500' : metrics.cpu > 60 ? 'bg-amber-500' : 'bg-emerald-500'}`} 
                style={{ width: `${metrics.cpu}%` }}
              ></div>
            </div>
          </div>

          {/* Memory Card */}
          <div className="bg-[#0d1424] border border-[#1e293b] p-6 rounded-xl relative overflow-hidden">
            <div className="flex items-center justify-between mb-4">
              <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Memory Allocation</span>
              <HardDrive className="h-5 w-5 text-cyan-400" />
            </div>
            <div className="flex items-baseline space-x-2">
              <span className="text-3xl font-extrabold text-white">{metrics.memory}%</span>
            </div>
            <div className="mt-3 w-full bg-[#162238] rounded-full h-1.5 overflow-hidden">
              <div 
                className="h-full rounded-full bg-cyan-500" 
                style={{ width: `${metrics.memory}%` }}
              ></div>
            </div>
          </div>

          {/* Network Throughput */}
          <div className="bg-[#0d1424] border border-[#1e293b] p-6 rounded-xl relative overflow-hidden">
            <div className="flex items-center justify-between mb-4">
              <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Network IO</span>
              <Activity className="h-5 w-5 text-emerald-400" />
            </div>
            <div className="flex items-baseline space-x-2">
              <span className="text-2xl font-extrabold text-white">
                {metrics.networkIn} <span className="text-xs font-normal text-gray-400">MB/s</span>
              </span>
            </div>
            <p className="text-[10px] text-gray-400 mt-2">
              TX: {metrics.networkOut} MB/s | RX: {metrics.networkIn} MB/s
            </p>
          </div>

          {/* Latency */}
          <div className="bg-[#0d1424] border border-[#1e293b] p-6 rounded-xl relative overflow-hidden">
            <div className="flex items-center justify-between mb-4">
              <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">API Latency</span>
              <Zap className="h-5 w-5 text-amber-400" />
            </div>
            <div className="flex items-baseline space-x-2">
              <span className="text-3xl font-extrabold text-white">{metrics.latency}ms</span>
            </div>
            <span className={`text-[10px] inline-block px-2 py-0.5 rounded-full mt-2 font-medium ${
              metrics.latency > 200 ? 'bg-rose-950/40 text-rose-400' : 'bg-emerald-950/40 text-emerald-400'
            }`}>
              {metrics.latency > 200 ? 'Critical spike warning' : 'Normal latency target'}
            </span>
          </div>

          {/* HTTP Error Rate */}
          <div className="bg-[#0d1424] border border-[#1e293b] p-6 rounded-xl relative overflow-hidden">
            <div className="flex items-center justify-between mb-4">
              <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">API Error Rate</span>
              <AlertOctagon className="h-5 w-5 text-rose-400" />
            </div>
            <div className="flex items-baseline space-x-2">
              <span className="text-3xl font-extrabold text-white">{metrics.errorRate}%</span>
            </div>
            <span className={`text-[10px] inline-block px-2 py-0.5 rounded-full mt-2 font-medium ${
              metrics.errorRate > 2.0 ? 'bg-rose-950/40 text-rose-400 border border-rose-900/30' : 'bg-emerald-950/40 text-emerald-400'
            }`}>
              {metrics.errorRate > 2.0 ? 'Exceeds SLA threshold' : 'Optimal operations'}
            </span>
          </div>
        </div>
      )}

      {/* Grafana-style Chart Widgets Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* CPU & Memory Chart */}
        <div className="bg-[#0d1424] border border-[#1e293b] p-6 rounded-xl">
          <h3 className="text-sm font-semibold text-white mb-6 uppercase tracking-wider">CPU & Memory Utilization (%)</h3>
          <div className="h-80 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={series}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" vertical={false} />
                <XAxis dataKey="time" stroke="#6b7280" fontSize={11} tickLine={false} />
                <YAxis stroke="#6b7280" fontSize={11} tickLine={false} domain={[0, 100]} />
                <Tooltip content={<ChartTooltip unit="%" />} />
                <Line type="monotone" dataKey="cpu" name="CPU" stroke="#6366f1" strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
                <Line type="monotone" dataKey="memory" name="Memory" stroke="#06b6d4" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Latency & Error Rate Chart */}
        <div className="bg-[#0d1424] border border-[#1e293b] p-6 rounded-xl">
          <h3 className="text-sm font-semibold text-white mb-6 uppercase tracking-wider">API Latency (ms) & Error Rate (%)</h3>
          <div className="h-80 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={series}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" vertical={false} />
                <XAxis dataKey="time" stroke="#6b7280" fontSize={11} tickLine={false} />
                <YAxis yAxisId="left" stroke="#6b7280" fontSize={11} tickLine={false} />
                <YAxis yAxisId="right" orientation="right" stroke="#6b7280" fontSize={11} tickLine={false} />
                <Tooltip content={<ChartTooltip unit="" />} />
                <Line yAxisId="left" type="monotone" dataKey="latency" name="Latency (ms)" stroke="#f59e0b" strokeWidth={2} dot={false} />
                <Line yAxisId="right" type="monotone" dataKey="errorRate" name="Error Rate (%)" stroke="#ef4444" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Alerts and Incidents Tables */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Active Alert Center */}
        <div className="bg-[#0d1424] border border-[#1e293b] p-6 rounded-xl lg:col-span-2">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-sm font-semibold text-white uppercase tracking-wider flex items-center space-x-2">
              <AlertTriangle className="h-4 w-4 text-amber-500" />
              <span>Active Alert Center</span>
            </h3>
            <span className="bg-[#162238] text-[10px] text-gray-400 px-2 py-0.5 rounded border border-[#1e293b]">
              Live Feed
            </span>
          </div>

          <div className="overflow-x-auto">
            {alerts.length === 0 ? (
              <div className="text-center py-8 text-gray-500 text-xs">
                No active alarms firing on this cluster.
              </div>
            ) : (
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-[#1e293b] text-gray-400 font-semibold">
                    <th className="pb-3">Source</th>
                    <th className="pb-3">Alert Details</th>
                    <th className="pb-3">Severity</th>
                    <th className="pb-3">Status</th>
                    <th className="pb-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e293b]/50">
                  {alerts.map((alert) => (
                    <tr key={alert.id} className="text-gray-300">
                      <td className="py-4 capitalize font-semibold text-indigo-400">{alert.source}</td>
                      <td className="py-4">
                        <p className="font-semibold text-white text-xs">{alert.title}</p>
                        <p className="text-[10px] text-gray-500 max-w-sm truncate">{alert.message}</p>
                      </td>
                      <td className="py-4">
                        <span className={`px-2 py-0.5 rounded text-[9px] font-semibold border ${
                          alert.severity === 'critical' 
                            ? 'bg-rose-950/40 text-rose-400 border-rose-900/30' 
                            : 'bg-amber-950/40 text-amber-400 border-amber-900/30'
                        }`}>
                          {alert.severity}
                        </span>
                      </td>
                      <td className="py-4 capitalize text-[10px]">{alert.status}</td>
                      <td className="py-4 text-right space-x-2">
                        {alert.status === 'active' && (
                          <button
                            onClick={() => handleAcknowledgeAlert(alert.id)}
                            className="bg-[#162238] border border-[#1e293b] hover:bg-[#203152] text-gray-300 px-2 py-1 rounded text-[10px] font-medium transition-colors"
                          >
                            Ack
                          </button>
                        )}
                        {alert.status !== 'resolved' && (
                          <button
                            onClick={() => handleResolveAlert(alert.id)}
                            className="bg-emerald-950/40 border border-emerald-900/30 hover:bg-emerald-950/60 text-emerald-400 px-2 py-1 rounded text-[10px] font-medium transition-colors"
                          >
                            Resolve
                          </button>
                        )}
                        {alert.status === 'resolved' && (
                          <span className="text-emerald-500 flex items-center justify-end text-[10px] font-medium space-x-1">
                            <CheckCircle className="h-3 w-3" />
                            <span>Done</span>
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Recent Incidents Panel */}
        <div className="bg-[#0d1424] border border-[#1e293b] p-6 rounded-xl">
          <h3 className="text-sm font-semibold text-white uppercase tracking-wider mb-6 flex items-center space-x-2">
            <AlertOctagon className="h-4 w-4 text-rose-500" />
            <span>Recent Incidents</span>
          </h3>

          <div className="space-y-4">
            {incidents.length === 0 ? (
              <div className="text-center py-6 text-gray-500 text-xs">
                No recorded incidents.
              </div>
            ) : (
              incidents.map((incident) => (
                <div key={incident.id} className="p-4 rounded-lg bg-[#0a101d] border border-[#1e293b]/60 hover:border-indigo-500/30 transition-all">
                  <div className="flex items-center justify-between mb-2">
                    <span className={`px-2 py-0.5 rounded text-[9px] font-semibold border capitalize ${
                      incident.severity === 'critical'
                        ? 'bg-rose-950/40 text-rose-400 border-rose-900/30'
                        : incident.severity === 'high'
                        ? 'bg-amber-950/40 text-amber-400 border-amber-900/30'
                        : 'bg-indigo-950/40 text-indigo-400 border-indigo-900/30'
                    }`}>
                      {incident.severity}
                    </span>
                    <span className="text-[10px] text-gray-500 flex items-center space-x-1">
                      <Clock className="h-3 w-3" />
                      <span>{new Date(incident.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                    </span>
                  </div>
                  <h4 className="text-xs font-bold text-white mb-1 truncate">{incident.title}</h4>
                  <p className="text-[10px] text-gray-400 line-clamp-2 mb-3">{incident.description}</p>
                  <div className="flex items-center justify-between text-[9px] border-t border-[#1e293b]/50 pt-2 text-gray-500">
                    <span>Status: <span className="text-gray-300 font-semibold capitalize">{incident.status}</span></span>
                    <span>#{incident.id}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

import React, { useEffect, useState } from 'react';
import { incidentsService } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { 
  AlertTriangle, 
  Clock, 
  Plus, 
  X, 
  CheckCircle2, 
  Compass, 
  Trash2 
} from 'lucide-react';

interface Incident {
  id: number;
  project_id: number | null;
  title: string;
  description: string;
  severity: string;
  status: string;
  created_at: string;
  updated_at: string;
  timeline: Array<{ timestamp: string; event: string; user: string }>;
}

export const IncidentCenter: React.FC = () => {
  const { user } = useAuth();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string>('');

  // Create Incident Modal Form State
  const [showCreateModal, setShowCreateModal] = useState<boolean>(false);
  const [newTitle, setNewTitle] = useState<string>('');
  const [newDesc, setNewDesc] = useState<string>('');
  const [newSeverity, setNewSeverity] = useState<string>('medium');

  // Timeline update form state
  const [customEventText, setCustomEventText] = useState<string>('');
  const [updatingTimeline, setUpdatingTimeline] = useState<boolean>(false);

  const fetchIncidents = async () => {
    try {
      const data = await incidentsService.getIncidents();
      setIncidents(data);
      if (selectedIncident) {
        const updated = data.find((i: Incident) => i.id === selectedIncident.id);
        if (updated) setSelectedIncident(updated);
      }
      setError('');
    } catch (err) {
      console.error("Failed to load incidents", err);
      setError("Failed to sync incidents control list.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, []);

  const handleCreateIncident = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) return;

    try {
      const created = await incidentsService.createIncident({
        title: newTitle,
        description: newDesc,
        severity: newSeverity,
        project_id: 1, // Default seed project
      });
      setShowCreateModal(false);
      setNewTitle('');
      setNewDesc('');
      setNewSeverity('medium');
      fetchIncidents();
      setSelectedIncident(created);
    } catch (err) {
      console.error(err);
      alert("Failed to declare incident.");
    }
  };

  const handleUpdateStatus = async (statusVal: string) => {
    if (!selectedIncident) return;
    try {
      const updated = await incidentsService.updateIncident(selectedIncident.id, {
        status: statusVal
      });
      setSelectedIncident(updated);
      fetchIncidents();
    } catch (err) {
      console.error(err);
    }
  };

  const handleUpdateSeverity = async (sevVal: string) => {
    if (!selectedIncident) return;
    try {
      const updated = await incidentsService.updateIncident(selectedIncident.id, {
        severity: sevVal
      });
      setSelectedIncident(updated);
      fetchIncidents();
    } catch (err) {
      console.error(err);
    }
  };

  const handleAddTimelineEvent = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedIncident || !customEventText.trim()) return;
    setUpdatingTimeline(true);

    try {
      const updated = await incidentsService.updateIncident(selectedIncident.id, {
        timeline_event: customEventText
      });
      setSelectedIncident(updated);
      setCustomEventText('');
      fetchIncidents();
    } catch (err) {
      console.error(err);
    } finally {
      setUpdatingTimeline(false);
    }
  };

  const handleDeleteIncident = async (id: number) => {
    if (!window.confirm("Are you sure you want to delete this incident log?")) return;
    try {
      await incidentsService.deleteIncident(id);
      setSelectedIncident(null);
      fetchIncidents();
    } catch (err) {
      console.error(err);
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev?.toLowerCase()) {
      case 'critical': return 'bg-rose-950/40 text-rose-400 border-rose-900/40';
      case 'high': return 'bg-amber-950/40 text-amber-400 border-amber-900/40';
      case 'medium': return 'bg-blue-950/40 text-blue-400 border-blue-900/40';
      default: return 'bg-gray-800 text-gray-400 border-gray-700';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'resolved': return <CheckCircle2 className="h-4 w-4 text-emerald-400" />;
      case 'investigating': return <Compass className="h-4 w-4 text-amber-400 animate-spin" />;
      default: return <Clock className="h-4 w-4 text-rose-400" />;
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-[50vh] space-y-4">
        <div className="h-10 w-10 border-4 border-indigo-500 border-t-transparent rounded-full animate-spin"></div>
        <p className="text-gray-400 text-sm">Synchronizing incident logs...</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {error && (
        <div className="bg-rose-950/30 border border-rose-900/50 text-rose-400 text-xs px-4 py-3 rounded-lg">
          {error}
        </div>
      )}
      <div className="flex items-center justify-between">
        <p className="text-xs text-gray-400">Declare active cluster faults and record operational post-mortem reports.</p>
        
        {/* Create incident button */}
        {user?.role !== 'viewer' && (
          <button
            onClick={() => setShowCreateModal(true)}
            className="bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold px-4 py-2.5 rounded-lg flex items-center space-x-2 transition-colors"
          >
            <Plus className="h-4 w-4" />
            <span>Declare Incident</span>
          </button>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Incidents master list */}
        <div className="space-y-4 lg:col-span-1">
          <h3 className="text-xs font-bold text-gray-400 uppercase tracking-widest">Active Incident Logs</h3>
          
          <div className="space-y-3 overflow-y-auto max-h-[600px] pr-1">
            {incidents.length === 0 ? (
              <div className="text-center py-8 text-gray-500 text-xs bg-[#0d1424] border border-[#1e293b] rounded-xl">
                No active incidents reported.
              </div>
            ) : (
              incidents.map((incident) => (
                <button
                  key={incident.id}
                  onClick={() => setSelectedIncident(incident)}
                  className={`w-full text-left p-4 rounded-xl border transition-all flex flex-col ${
                    selectedIncident?.id === incident.id
                      ? 'bg-indigo-600/10 border-indigo-500/50'
                      : 'bg-[#0d1424] border-[#1e293b] hover:border-gray-700'
                  }`}
                >
                  <div className="flex items-center justify-between w-full mb-2">
                    <span className={`px-2 py-0.5 rounded text-[8px] font-extrabold uppercase border ${getSeverityBadge(incident.severity)}`}>
                      {incident.severity}
                    </span>
                    <span className="text-[10px] text-gray-500 flex items-center space-x-1">
                      {getStatusIcon(incident.status)}
                      <span className="capitalize">{incident.status}</span>
                    </span>
                  </div>
                  <h4 className="text-xs font-bold text-white mb-1.5 line-clamp-1">{incident.title}</h4>
                  <p className="text-[10px] text-gray-400 line-clamp-2 mb-3">{incident.description}</p>
                  <div className="w-full border-t border-[#1e293b]/50 pt-2 flex items-center justify-between text-[9px] text-gray-500">
                    <span>Declared: {new Date(incident.created_at).toLocaleDateString()}</span>
                    <span>#{incident.id}</span>
                  </div>
                </button>
              ))
            )}
          </div>
        </div>

        {/* Incident Detail and Timeline pane */}
        <div className="lg:col-span-2">
          {selectedIncident ? (
            <div className="bg-[#0d1424] border border-[#1e293b] rounded-xl p-6 space-y-6">
              {/* Header */}
              <div className="flex flex-wrap items-start justify-between gap-4 border-b border-[#1e293b] pb-6">
                <div>
                  <div className="flex items-center space-x-2 text-gray-500 text-[10px] mb-2 font-mono">
                    <span>Incident Reference ID: #{selectedIncident.id}</span>
                    <span>•</span>
                    <span>Created: {new Date(selectedIncident.created_at).toLocaleString()}</span>
                  </div>
                  <h3 className="text-lg font-bold text-white">{selectedIncident.title}</h3>
                </div>

                {user?.role !== 'viewer' ? (
                  <div className="flex items-center space-x-3">
                    {/* Status Select dropdown */}
                    <select
                      value={selectedIncident.status}
                      onChange={(e) => handleUpdateStatus(e.target.value)}
                      className="bg-[#162238] border border-[#1e293b] text-gray-300 text-xs px-2.5 py-1.5 rounded-lg focus:outline-none focus:border-indigo-500 cursor-pointer"
                    >
                      <option value="open">Open</option>
                      <option value="investigating">Investigating</option>
                      <option value="resolved">Resolved</option>
                    </select>

                    {/* Severity Select dropdown */}
                    <select
                      value={selectedIncident.severity}
                      onChange={(e) => handleUpdateSeverity(e.target.value)}
                      className="bg-[#162238] border border-[#1e293b] text-gray-300 text-xs px-2.5 py-1.5 rounded-lg focus:outline-none focus:border-indigo-500 cursor-pointer"
                    >
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                      <option value="critical">Critical</option>
                    </select>
                    
                    {user?.role === 'admin' && (
                      <button
                        onClick={() => handleDeleteIncident(selectedIncident.id)}
                        className="p-1.5 bg-rose-950/20 text-rose-400 border border-rose-900/30 rounded-lg hover:bg-rose-900/30 transition-colors"
                        title="Delete log"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    )}
                  </div>
                ) : (
                  <div className="flex items-center space-x-2">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border capitalize ${getSeverityBadge(selectedIncident.severity)}`}>
                      {selectedIncident.severity}
                    </span>
                    <span className="bg-[#162238] text-[10px] text-gray-300 px-2 py-0.5 rounded border border-[#1e293b] capitalize">
                      {selectedIncident.status}
                    </span>
                  </div>
                )}
              </div>

              {/* Description */}
              <div>
                <h5 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-2">Description</h5>
                <p className="text-xs text-gray-300 leading-relaxed bg-[#0a101d] p-4 border border-[#1e293b]/60 rounded-lg whitespace-pre-wrap">
                  {selectedIncident.description || "No description provided."}
                </p>
              </div>

              {/* Timeline logger list */}
              <div>
                <h5 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-4">Operations incident Timeline</h5>
                
                <div className="relative border-l border-[#1e293b] ml-3 pl-6 space-y-6 text-xs">
                  {selectedIncident.timeline && selectedIncident.timeline.map((item, idx) => (
                    <div key={idx} className="relative">
                      {/* Timeline dot bullet */}
                      <span className="absolute -left-[31px] top-0.5 bg-[#090d16] border border-[#1e293b] h-3.5 w-3.5 rounded-full flex items-center justify-center">
                        <span className="h-1.5 w-1.5 rounded-full bg-indigo-400"></span>
                      </span>

                      {/* Header timestamp */}
                      <div className="flex items-center space-x-2 text-gray-500 mb-1">
                        <span className="font-semibold text-gray-400">{item.user}</span>
                        <span>•</span>
                        <span>{new Date(item.timestamp).toLocaleString()}</span>
                      </div>

                      {/* Message body */}
                      <p className="text-gray-300 font-medium leading-relaxed bg-[#0b101c] p-2.5 rounded border border-[#1e293b]/30">
                        {item.event}
                      </p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Timeline appender form */}
              {user?.role !== 'viewer' && (
                <form onSubmit={handleAddTimelineEvent} className="border-t border-[#1e293b] pt-6 flex gap-3">
                  <input
                    type="text"
                    required
                    value={customEventText}
                    onChange={(e) => setCustomEventText(e.target.value)}
                    placeholder="Append timeline update, e.g., 'Completed rollback of ingress deployment'..."
                    className="flex-1 bg-[#0d1424] border border-[#1e293b] rounded-lg px-4 py-2 text-xs text-gray-200 placeholder-gray-600 focus:outline-none focus:border-indigo-500"
                  />
                  <button
                    type="submit"
                    disabled={updatingTimeline || !customEventText.trim()}
                    className="bg-[#162238] border border-[#1e293b] hover:bg-[#203152] text-gray-200 text-xs font-semibold px-4 py-2 rounded-lg transition-colors shrink-0 disabled:opacity-50"
                  >
                    {updatingTimeline ? 'Saving...' : 'Post Log'}
                  </button>
                </form>
              )}
            </div>
          ) : (
            <div className="bg-[#0d1424] border border-[#1e293b] rounded-xl p-12 text-center text-gray-500 text-xs h-[50vh] flex flex-col justify-center items-center space-y-2">
              <AlertTriangle className="h-8 w-8 text-gray-600 animate-pulse" />
              <span>Select an incident from the control sidebar to inspect timelines and operations logs.</span>
            </div>
          )}
        </div>
      </div>

      {/* Declarations form Modal Dialog */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm px-4">
          <div className="bg-[#0d1424] border border-[#1e293b] w-full max-w-lg rounded-xl overflow-hidden shadow-2xl animate-scaleIn">
            <div className="border-b border-[#1e293b] px-6 py-4 flex items-center justify-between">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">Declare Fault Incident</h3>
              <button onClick={() => setShowCreateModal(false)} className="text-gray-400 hover:text-white">
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleCreateIncident} className="p-6 space-y-4">
              <div>
                <label className="block text-xs font-semibold text-gray-400 uppercase mb-2">Incident Title</label>
                <input
                  type="text"
                  required
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="e.g. Postgres Replica Lag exceeding 10 seconds"
                  className="w-full bg-[#070b13] border border-[#1e293b] rounded-lg px-4 py-2.5 text-xs text-gray-100 placeholder-gray-600 focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-gray-400 uppercase mb-2">Fault Description</label>
                <textarea
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  placeholder="Specify system errors, target pods, region, impact etc."
                  rows={4}
                  className="w-full bg-[#070b13] border border-[#1e293b] rounded-lg px-4 py-2.5 text-xs text-gray-100 placeholder-gray-600 focus:outline-none focus:border-indigo-500 resize-none"
                ></textarea>
              </div>

              <div>
                <label className="block text-xs font-semibold text-gray-400 uppercase mb-2">Initial Severity Target</label>
                <select
                  value={newSeverity}
                  onChange={(e) => setNewSeverity(e.target.value)}
                  className="w-full bg-[#070b13] border border-[#1e293b] rounded-lg px-4 py-2.5 text-xs text-gray-100 focus:outline-none focus:border-indigo-500 cursor-pointer"
                >
                  <option value="low">Low (Minor configuration warning)</option>
                  <option value="medium">Medium (Degraded performance alert)</option>
                  <option value="high">High (Service disruption incident)</option>
                  <option value="critical">Critical (Core application down / Outage)</option>
                </select>
              </div>

              <div className="pt-4 border-t border-[#1e293b] flex justify-end space-x-3">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="bg-transparent hover:bg-[#162238] border border-[#1e293b] text-gray-400 hover:text-white text-xs font-semibold px-4 py-2.5 rounded-lg transition-all"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold px-6 py-2.5 rounded-lg transition-all shadow-md shadow-indigo-600/10"
                >
                  Declare Outage
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

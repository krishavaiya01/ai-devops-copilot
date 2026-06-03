import React, { useState, useEffect } from 'react';
import { logsService } from '../services/api';
import { 
  Terminal, 
  Upload, 
  AlertCircle, 
  Copy, 
  Check, 
  FileText, 
  TrendingDown, 
  Users, 
  DollarSign, 
  ShieldAlert, 
  Layers, 
  Server, 
  Database, 
  Network, 
  Cloud, 
  Lock, 
  Workflow, 
  Cpu, 
  Radio, 
  AlertTriangle 
} from 'lucide-react';

interface BusinessImpact {
  affected_users: number;
  failed_transactions: number;
  estimated_revenue_impact_usd: number;
  summary: string;
}

interface TimelineEvent {
  timestamp: string;
  event: string;
  confidence_score: number;
}

interface Analysis {
  executive_summary: string;
  primary_root_causes: string[];
  confidence_score: number;
  supporting_evidence: string;
  contributing_factors: string;
  infrastructure_issues: string;
  kubernetes_issues: string;
  database_issues: string;
  redis_issues: string;
  cloud_issues: string;
  security_issues: string;
  kafka_issues: string;
  container_issues: string;
  cicd_issues: string;
  business_impact: BusinessImpact;
  severity_classification: string;
  immediate_actions: string;
  long_term_prevention: string;
  critical_findings_missed: string[];
  timeline_reconstruction: TimelineEvent[];
  documentation_links: string[];
}

interface LogRecord {
  id: number;
  content: string;
  analysis: Analysis | null;
  created_at: string;
}

export const LogAnalyzer: React.FC = () => {
  const [logContent, setLogContent] = useState<string>('');
  const [analyzing, setAnalyzing] = useState<boolean>(false);
  const [result, setResult] = useState<LogRecord | null>(null);
  const [history, setHistory] = useState<LogRecord[]>([]);
  const [copied, setCopied] = useState<boolean>(false);
  const [error, setError] = useState<string>('');

  const fetchHistory = async () => {
    try {
      const logs = await logsService.getLogs();
      setHistory(logs);
    } catch (err) {
      console.error("Failed to load logs history:", err);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const handleAnalyze = async () => {
    if (!logContent.trim()) return;
    setAnalyzing(true);
    setError('');
    setResult(null);

    try {
      const data = await logsService.analyze(logContent);
      setResult(data);
      setHistory((prev) => [data, ...prev]);
      fetchHistory();
    } catch (err: any) {
      console.error(err);
      setError(err.response?.data?.detail || 'AI SRE Analyzer call failed. Check server status.');
    } finally {
      setAnalyzing(false);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      setLogContent(text);
    };
    reader.readAsText(file);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getSeverityBadgeColor = (sev: string) => {
    const s = sev?.toUpperCase();
    if (s === 'P1') return 'bg-rose-950/40 text-rose-400 border-rose-900/50';
    if (s === 'P2') return 'bg-amber-950/40 text-amber-400 border-amber-900/50';
    if (s === 'P3') return 'bg-blue-950/40 text-blue-400 border-blue-900/50';
    if (s === 'P4') return 'bg-emerald-950/40 text-emerald-400 border-emerald-900/50';
    return 'bg-gray-800 text-gray-400 border-gray-700';
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
      {/* Console Input pane */}
      <div className="lg:col-span-2 space-y-6">
        <div className="bg-[#0d1424] border border-[#1e293b] p-6 rounded-xl flex flex-col h-[280px]">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-white uppercase tracking-wider flex items-center space-x-2">
              <Terminal className="h-5 w-5 text-indigo-400" />
              <span>Diagnostic Raw Console Feed</span>
            </h3>
            
            {/* File Upload Button */}
            <label className="flex items-center space-x-1.5 bg-[#162238] border border-[#1e293b] hover:bg-[#203152] text-gray-300 text-xs px-3 py-1.5 rounded-lg cursor-pointer transition-colors font-medium">
              <Upload className="h-3.5 w-3.5" />
              <span>Upload Log File</span>
              <input type="file" onChange={handleFileUpload} accept=".log,.txt" className="hidden" />
            </label>
          </div>

          <textarea
            value={logContent}
            onChange={(e) => setLogContent(e.target.value)}
            placeholder="Paste raw log lines, Security logs, EKS warnings, or Kafka backlog alerts here..."
            className="flex-1 w-full bg-[#070b13] border border-[#1e293b] rounded-lg p-4 text-xs font-mono text-emerald-400 placeholder-gray-600 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 resize-none leading-relaxed"
          ></textarea>

          {error && (
            <p className="text-rose-400 text-xs mt-3 flex items-center space-x-1">
              <AlertCircle className="h-3.5 w-3.5 shrink-0" />
              <span>{error}</span>
            </p>
          )}

          <div className="mt-4 flex items-center justify-between">
            <button
              onClick={() => {
                setLogContent('');
                setResult(null);
              }}
              className="text-xs text-gray-400 hover:text-gray-200 transition-colors font-semibold"
            >
              Clear Terminal
            </button>
            <button
              onClick={handleAnalyze}
              disabled={analyzing || !logContent.trim()}
              className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-xs font-semibold px-6 py-2.5 rounded-lg transition-colors flex items-center space-x-2"
            >
              {analyzing ? (
                <>
                  <div className="h-3.5 w-3.5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                  <span>Running Advanced Diagnostics...</span>
                </>
              ) : (
                <span>Analyze SRE Incident</span>
              )}
            </button>
          </div>
        </div>

        {/* Upgraded AI SRE Report */}
        {result && result.analysis && (
          <div className="bg-[#0d1424] border border-[#1e293b] rounded-xl overflow-hidden shadow-2xl animate-fadeIn space-y-6 p-6">
            
            {/* Header / Meta */}
            <div className="flex flex-wrap items-center justify-between border-b border-[#1e293b] pb-4 gap-4">
              <div>
                <h4 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2">
                  <ShieldAlert className="h-4 w-4 text-rose-500 animate-pulse" />
                  <span>SRE Outage Control Incident Report</span>
                </h4>
                <p className="text-[10px] text-gray-500 font-mono mt-0.5">Correlation scan generated: {new Date(result.created_at).toLocaleString()}</p>
              </div>
              <div className="flex items-center space-x-3">
                {/* Confidence Score Badge */}
                <div className="flex items-center space-x-1.5 bg-indigo-950/40 border border-indigo-900/40 px-3 py-1 rounded-full text-indigo-400 text-xs">
                  <span className="font-semibold">Confidence:</span>
                  <span className="font-bold">{result.analysis?.confidence_score || 95}%</span>
                </div>
                
                <span className={`text-xs font-extrabold px-3 py-1 rounded-full border ${getSeverityBadgeColor(result.analysis?.severity_classification || 'P5')}`}>
                  Severity: {result.analysis?.severity_classification || 'P5'}
                </span>
              </div>
            </div>

            {/* Executive summary banner */}
            <div className="bg-[#111827] border-l-4 border-indigo-500 p-4 rounded-r-lg">
              <h5 className="text-[10px] font-bold text-indigo-400 uppercase tracking-widest mb-1">Executive Summary</h5>
              <p className="text-xs font-medium text-gray-200 leading-relaxed">{result.analysis?.executive_summary}</p>
            </div>

            {/* Business Impact Grid Metrics */}
            <div className="space-y-3">
              <h5 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">Incident Business & Financial Impact</h5>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-[#0a101d] border border-[#1e293b] p-4 rounded-lg flex items-center space-x-3.5">
                  <Users className="h-5 w-5 text-indigo-400" />
                  <div>
                    <span className="text-[10px] text-gray-500 block">Affected Users</span>
                    <span className="text-base font-extrabold text-white">{(result.analysis?.business_impact?.affected_users ?? 0).toLocaleString()}</span>
                  </div>
                </div>
                <div className="bg-[#0a101d] border border-[#1e293b] p-4 rounded-lg flex items-center space-x-3.5">
                  <TrendingDown className="h-5 w-5 text-amber-500" />
                  <div>
                    <span className="text-[10px] text-gray-500 block">Failed Transactions</span>
                    <span className="text-base font-extrabold text-white">{(result.analysis?.business_impact?.failed_transactions ?? 0).toLocaleString()}</span>
                  </div>
                </div>
                <div className="bg-[#0a101d] border border-[#1e293b] p-4 rounded-lg flex items-center space-x-3.5">
                  <DollarSign className="h-5 w-5 text-emerald-500" />
                  <div>
                    <span className="text-[10px] text-gray-500 block">Est. Revenue Loss</span>
                    <span className="text-base font-extrabold text-emerald-400">
                      ${(result.analysis?.business_impact?.estimated_revenue_impact_usd ?? 0).toLocaleString(undefined, { minimumFractionDigits: 2 })}
                    </span>
                  </div>
                </div>
              </div>
              {result.analysis?.business_impact?.summary && (
                <p className="text-xs text-gray-400 italic bg-[#0a101d]/50 p-3 rounded border border-[#1e293b]/40">
                  {result.analysis.business_impact.summary}
                </p>
              )}
            </div>

            {/* Core Diagnostics Split Panel */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Primary SRE Analysis (Multi-Root Cause) */}
              <div className="space-y-4">
                <div>
                  <h5 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-1.5">Primary Root Causes</h5>
                  <ol className="list-decimal list-inside text-xs text-gray-200 space-y-2 bg-[#0a101d] p-3 rounded-lg border border-[#1e293b]/50">
                    {result.analysis?.primary_root_causes ? (
                      result.analysis.primary_root_causes.map((rc, idx) => (
                        <li key={idx} className="font-semibold leading-relaxed">
                          {rc}
                        </li>
                      ))
                    ) : (
                      <li className="font-semibold leading-relaxed">No root causes identified.</li>
                    )}
                  </ol>
                </div>
                <div>
                  <h5 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-1.5">Supporting Evidence</h5>
                  <p className="text-xs text-gray-300 leading-relaxed bg-[#0a101d]/30 p-3 rounded border border-[#1e293b]/30">{result.analysis?.supporting_evidence}</p>
                </div>
                <div>
                  <h5 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-1.5">Contributing Factors</h5>
                  <p className="text-xs text-gray-300 leading-relaxed">{result.analysis?.contributing_factors}</p>
                </div>
              </div>

              {/* Infrastructure Component Telemetry Warnings */}
              <div className="bg-[#0a101d] border border-[#1e293b] p-4 rounded-xl space-y-3.5 text-xs">
                <h5 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-2 border-b border-[#1e293b] pb-2">Subsystem Warnings</h5>
                
                {result.analysis?.security_issues && result.analysis.security_issues !== 'None' && (
                  <div className="flex items-start space-x-2 bg-rose-950/20 border border-rose-900/30 p-2.5 rounded-lg">
                    <Lock className="h-4 w-4 text-rose-400 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-bold text-rose-400 block text-[11px]">Security Breach Alerts</span>
                      <span className="text-gray-300 text-[10px]">{result.analysis.security_issues}</span>
                    </div>
                  </div>
                )}
                {result.analysis?.kafka_issues && result.analysis.kafka_issues !== 'None' && (
                  <div className="flex items-start space-x-2 bg-amber-950/20 border border-amber-900/30 p-2.5 rounded-lg">
                    <Radio className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-bold text-amber-400 block text-[11px]">Kafka Streams Backlog</span>
                      <span className="text-gray-300 text-[10px]">{result.analysis.kafka_issues}</span>
                    </div>
                  </div>
                )}
                {result.analysis?.container_issues && result.analysis.container_issues !== 'None' && (
                  <div className="flex items-start space-x-2 bg-indigo-950/20 border border-indigo-900/30 p-2.5 rounded-lg">
                    <Cpu className="h-4 w-4 text-indigo-400 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-bold text-indigo-400 block text-[11px]">Container Limits & OOM</span>
                      <span className="text-gray-300 text-[10px]">{result.analysis.container_issues}</span>
                    </div>
                  </div>
                )}
                {result.analysis?.cicd_issues && result.analysis.cicd_issues !== 'None' && (
                  <div className="flex items-start space-x-2 bg-cyan-950/20 border border-cyan-900/30 p-2.5 rounded-lg">
                    <Workflow className="h-4 w-4 text-cyan-400 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-bold text-cyan-400 block text-[11px]">CI/CD Deployment Failure</span>
                      <span className="text-gray-300 text-[10px]">{result.analysis.cicd_issues}</span>
                    </div>
                  </div>
                )}

                <div className="pt-2 space-y-2 border-t border-[#1e293b]/60">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="text-gray-500 flex items-center space-x-1">
                      <Server className="h-3.5 w-3.5 text-indigo-400" />
                      <span>Host Server:</span>
                    </span>
                    <span className="text-gray-300 truncate max-w-[200px]">{result.analysis?.infrastructure_issues || 'Healthy'}</span>
                  </div>
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="text-gray-500 flex items-center space-x-1">
                      <Layers className="h-3.5 w-3.5 text-cyan-400" />
                      <span>Kubernetes Status:</span>
                    </span>
                    <span className="text-gray-300 truncate max-w-[200px]">{result.analysis?.kubernetes_issues || 'Healthy'}</span>
                  </div>
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="text-gray-500 flex items-center space-x-1">
                      <Database className="h-3.5 w-3.5 text-emerald-400" />
                      <span>PostgreSQL DB:</span>
                    </span>
                    <span className="text-gray-300 truncate max-w-[200px]">{result.analysis?.database_issues || 'Healthy'}</span>
                  </div>
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="text-gray-500 flex items-center space-x-1">
                      <Network className="h-3.5 w-3.5 text-rose-400" />
                      <span>Redis Cache:</span>
                    </span>
                    <span className="text-gray-300 truncate max-w-[200px]">{result.analysis?.redis_issues || 'Healthy'}</span>
                  </div>
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="text-gray-500 flex items-center space-x-1">
                      <Cloud className="h-3.5 w-3.5 text-amber-500" />
                      <span>Amazon Web Services:</span>
                    </span>
                    <span className="text-gray-300 truncate max-w-[200px]">{result.analysis?.cloud_issues || 'Healthy'}</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Timeline Reconstruction Stepper */}
            {result.analysis?.timeline_reconstruction && result.analysis.timeline_reconstruction.length > 0 && (
              <div className="border-t border-[#1e293b] pt-6">
                <h5 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-4">Chronological Incident Timeline Reconstruction</h5>
                <div className="relative border-l border-indigo-950 ml-3 pl-6 space-y-5 text-xs">
                  {result.analysis.timeline_reconstruction.map((item, idx) => (
                    <div key={idx} className="relative">
                      <span className="absolute -left-[31px] top-0.5 bg-[#090d16] border border-indigo-500/30 h-3.5 w-3.5 rounded-full flex items-center justify-center">
                        <span className="h-1.5 w-1.5 rounded-full bg-indigo-500"></span>
                      </span>
                      <div className="flex items-center justify-between text-[10px] text-gray-500 mb-1">
                        <span className="font-mono">{new Date(item.timestamp).toLocaleTimeString()} ({item.timestamp.split('T')[0]})</span>
                        <span className="bg-indigo-950/40 border border-indigo-900/40 px-2 py-0.5 rounded text-indigo-400 font-semibold font-mono">
                          Conf: {Math.round(item.confidence_score * 100)}%
                        </span>
                      </div>
                      <p className="text-gray-300 bg-[#0a101d] p-3 rounded-lg border border-[#1e293b]/40 font-medium">
                        {item.event}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Critical Findings Missed warnings */}
            {result.analysis?.critical_findings_missed && result.analysis.critical_findings_missed.length > 0 && (
              <div className="border-t border-[#1e293b] pt-6">
                <h5 className="text-[10px] font-bold text-rose-400 uppercase tracking-widest mb-2.5 flex items-center space-x-1.5">
                  <AlertTriangle className="h-4 w-4 text-rose-500" />
                  <span>Critical Findings Omitted From Main Alerts</span>
                </h5>
                <div className="flex flex-wrap gap-2">
                  {result.analysis.critical_findings_missed.map((finding, idx) => (
                    <span key={idx} className="bg-rose-950/30 border border-rose-900/40 text-rose-400 text-[10px] px-3 py-1 rounded-full font-semibold">
                      ⚠️ {finding}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Immediate Actions Playbook Commands */}
            <div className="border-t border-[#1e293b] pt-6">
              <div className="flex items-center justify-between mb-2">
                <h5 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">Immediate Mitigation Scripts</h5>
                <button
                  onClick={() => copyToClipboard(result.analysis?.immediate_actions || '')}
                  className="text-gray-400 hover:text-white flex items-center space-x-1 text-[10px] transition-colors"
                >
                  {copied ? (
                    <>
                      <Check className="h-3.5 w-3.5 text-emerald-400" />
                      <span className="text-emerald-400">Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="h-3.5 w-3.5" />
                      <span>Copy Playbook</span>
                    </>
                  )}
                </button>
              </div>
              <pre className="bg-[#070b13] border border-[#1e293b] rounded-lg p-4 overflow-x-auto text-[11px] font-mono text-indigo-300 leading-relaxed max-h-60">
                <code>{result.analysis?.immediate_actions}</code>
              </pre>
            </div>

            {/* Long term prevention */}
            <div className="border-t border-[#1e293b] pt-6 text-xs">
              <h5 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-2">Long-Term Prevention Plan</h5>
              <p className="text-gray-300 leading-relaxed whitespace-pre-line">{result.analysis?.long_term_prevention}</p>
            </div>

            {/* Documentation Links */}
            {result.analysis?.documentation_links && result.analysis.documentation_links.length > 0 && (
              <div className="border-t border-[#1e293b] pt-6 text-xs">
                <h5 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-2">SRE Knowledgebase Playbooks</h5>
                <div className="flex flex-wrap gap-2.5">
                  {result.analysis.documentation_links.map((link, index) => (
                    <a
                      key={index}
                      href={link}
                      target="_blank"
                      rel="noreferrer"
                      className="bg-[#162238] border border-[#1e293b] hover:bg-[#203152] text-indigo-400 text-xs px-3 py-1.5 rounded-lg transition-colors inline-flex items-center space-x-1.5"
                    >
                      <span>🔗</span>
                      <span className="truncate max-w-xs">{link}</span>
                    </a>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* History sidebar pane */}
      <div className="bg-[#0d1424] border border-[#1e293b] p-6 rounded-xl flex flex-col h-[280px] lg:h-auto">
        <h3 className="text-sm font-semibold text-white uppercase tracking-wider mb-4 flex items-center space-x-2">
          <FileText className="h-5 w-5 text-indigo-400" />
          <span>Audit Log History</span>
        </h3>
        
        <div className="flex-1 overflow-y-auto space-y-3 pr-1">
          {history.length === 0 ? (
            <div className="text-center py-8 text-gray-500 text-xs">
              No historical log analyses found.
            </div>
          ) : (
            history.map((item) => (
              <button
                key={item.id}
                onClick={() => setResult(item)}
                className={`w-full text-left p-3 rounded-lg border transition-all text-xs block ${
                  result?.id === item.id 
                    ? 'bg-indigo-600/10 border-indigo-500/50' 
                    : 'bg-[#0a101d] border-[#1e293b] hover:border-gray-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className={`text-[8px] font-extrabold uppercase px-1.5 py-0.5 rounded border ${
                    getSeverityBadgeColor(item.analysis?.severity_classification || 'P5')
                  }`}>
                    {item.analysis?.severity_classification || 'P5'}
                  </span>
                  <span className="text-[9px] text-gray-500">
                    {new Date(item.created_at).toLocaleDateString([], { month: 'short', day: '2-digit' })}
                  </span>
                </div>
                <p className="font-mono text-[10px] text-gray-400 truncate mb-1">
                  {item.content}
                </p>
                {item.analysis && (
                  <p className="text-[10px] text-gray-300 font-semibold truncate">
                    {item.analysis.primary_root_causes ? item.analysis.primary_root_causes[0] : 'Log telemetry'}
                  </p>
                )}
              </button>
            ))
          )}
        </div>
      </div>
    </div>
  );
};

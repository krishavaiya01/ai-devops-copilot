import React, { useState, useEffect, useRef } from 'react';
import { chatService } from '../services/api';
import { MessageSquare, Send, Cpu, Terminal, Shield, Sparkles } from 'lucide-react';

interface ChatMessage {
  id: number;
  session_id: string;
  role: string;
  content: string;
  timestamp: string;
}

export const AIChat: React.FC = () => {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputValue, setInputValue] = useState<string>('');
  const [sending, setSending] = useState<boolean>(false);
  const [sessionId] = useState<string>(() => `session-${Math.random().toString(36).substr(2, 9)}`);
  const messagesEndRef = useRef<HTMLDivElement | null>(null);

  const fetchHistory = async () => {
    try {
      const data = await chatService.getSessionMessages(sessionId);
      setMessages(data);
    } catch (err) {
      console.error("Failed to load chat history:", err);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [sessionId]);

  useEffect(() => {
    // Scroll to bottom whenever messages list changes
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSendMessage = async (text: string) => {
    if (!text.trim() || sending) return;
    setSending(true);
    setInputValue('');

    // Prepend user message locally to avoid UI lag
    const mockUserMsg: ChatMessage = {
      id: Date.now(),
      session_id: sessionId,
      role: 'user',
      content: text,
      timestamp: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, mockUserMsg]);

    try {
      const response = await chatService.sendMessage(sessionId, text);
      setMessages((prev) => [...prev, response]);
    } catch (err) {
      console.error(err);
      // Insert mock system error warning
      const mockSystemError: ChatMessage = {
        id: Date.now() + 1,
        session_id: sessionId,
        role: 'assistant',
        content: "**System alert**: Failed to communicate with AI core endpoint. Please review backend connections.",
        timestamp: new Date().toISOString(),
      };
      setMessages((prev) => [...prev, mockSystemError]);
    } finally {
      setSending(false);
    }
  };

  const handleFormSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    handleSendMessage(inputValue);
  };

  const promptChips = [
    { label: "Docker Exit 137", query: "Explain Docker container exit code 137 and what commands I should run to debug it." },
    { label: "K8s Pod Restarting", query: "My Kubernetes Pod is restarting repeatedly (CrashLoopBackOff). Explain steps to troubleshoot." },
    { label: "AWS Cost Optimization", query: "Suggest 5 actionable ideas to reduce monthly cost on AWS EC2 and EBS storage." },
    { label: "Check Linux RAM", query: "What commands should I run on a Linux server to find out which processes are consuming the most RAM?" },
  ];

  return (
    <div className="bg-[#0d1424] border border-[#1e293b] rounded-xl flex flex-col h-[75vh] shadow-2xl overflow-hidden relative">
      {/* Header bar */}
      <div className="border-b border-[#1e293b] px-6 py-4 bg-[#111827] flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="h-9 w-9 rounded-lg bg-indigo-500/10 border border-indigo-500/25 flex items-center justify-center text-indigo-400">
            <Cpu className="h-5 w-5 animate-pulse" />
          </div>
          <div>
            <h3 className="text-xs font-bold text-white uppercase tracking-wider">DevOps SRE AI Copilot</h3>
            <span className="text-[10px] text-gray-500">Contextual troubleshooting session active</span>
          </div>
        </div>

        <div className="flex items-center space-x-2 text-[10px] text-indigo-400 bg-indigo-950/30 px-3 py-1 rounded-full border border-indigo-900/30">
          <Sparkles className="h-3.5 w-3.5" />
          <span>Powered by Gemini 2.5 Flash</span>
        </div>
      </div>

      {/* Message list container */}
      <div className="flex-1 overflow-y-auto p-6 space-y-6 bg-[#090d16]/30">
        {messages.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-center max-w-md mx-auto space-y-6">
            <MessageSquare className="h-10 w-10 text-gray-700" />
            <div className="space-y-2">
              <h4 className="text-sm font-semibold text-white">Ask your SRE Assistant</h4>
              <p className="text-xs text-gray-400 leading-relaxed">
                Troubleshoot Docker, Kubernetes clusters, AWS cloud networks, or Linux servers.
                Enter tracebacks, query CLI command options, or request cloud cost savings advice.
              </p>
            </div>

            {/* Quick Prompt chips */}
            <div className="grid grid-cols-2 gap-3 w-full pt-4">
              {promptChips.map((chip, idx) => (
                <button
                  key={idx}
                  onClick={() => handleSendMessage(chip.query)}
                  className="bg-[#0d1424] border border-[#1e293b] hover:border-indigo-500/40 text-gray-300 hover:text-white p-3 rounded-lg text-left text-[11px] font-medium transition-all"
                >
                  <span className="text-indigo-400 block mb-1">⚡ {chip.label}</span>
                  <span className="text-gray-500 line-clamp-1">{chip.query}</span>
                </button>
              ))}
            </div>
          </div>
        ) : (
          messages.map((msg) => {
            const isUser = msg.role === 'user';
            return (
              <div
                key={msg.id}
                className={`flex w-full ${isUser ? 'justify-end' : 'justify-start'} animate-fadeIn`}
              >
                <div
                  className={`max-w-3xl rounded-xl p-4 text-xs leading-relaxed whitespace-pre-wrap ${isUser
                      ? 'bg-indigo-600 text-white rounded-tr-none'
                      : 'bg-[#111827] border border-[#1e293b] text-gray-200 rounded-tl-none'
                    }`}
                >
                  {/* Sender badge header */}
                  <div className="flex items-center space-x-1.5 mb-2 text-[10px] text-gray-400 font-semibold uppercase tracking-wider">
                    {isUser ? (
                      <>
                        <Shield className="h-3 w-3 text-indigo-200" />
                        <span>SRE Operator</span>
                      </>
                    ) : (
                      <>
                        <Terminal className="h-3 w-3 text-indigo-400" />
                        <span className="text-indigo-400">Copilot AI</span>
                      </>
                    )}
                  </div>
                  <div className="font-medium">{msg.content}</div>
                </div>
              </div>
            );
          })
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input submit form */}
      <form onSubmit={handleFormSubmit} className="border-t border-[#1e293b] p-4 bg-[#111827] flex gap-3">
        <input
          type="text"
          value={inputValue}
          onChange={(e) => setInputValue(e.target.value)}
          placeholder="Ask a question or paste error logs..."
          className="flex-1 bg-[#090d16] border border-[#1e293b] rounded-lg px-4 py-3 text-xs text-gray-200 placeholder-gray-600 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500"
        />
        <button
          type="submit"
          disabled={sending || !inputValue.trim()}
          className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white p-3 rounded-lg flex items-center justify-center transition-colors shrink-0"
        >
          {sending ? (
            <div className="h-4 w-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
          ) : (
            <Send className="h-4 w-4" />
          )}
        </button>
      </form>
    </div>
  );
};

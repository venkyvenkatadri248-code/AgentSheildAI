import React, { useState, useEffect, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Send,
  Square,
  Bot,
  User as UserIcon,
  Plus,
  Trash2,
  Edit2,
  Copy,
  Check,
  Shield,
  ShieldAlert,
  Search,
  Sparkles,
  ChevronDown
} from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { api } from '../services/api';
import { Agent, Conversation, Message } from '../types';
import { Badge } from '../components/Badge';

export const ChatPage: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const agentKeyParam = searchParams.get('agent') || 'research_agent';

  const [agents, setAgents] = useState<Agent[]>([]);
  const [currentAgent, setCurrentAgent] = useState<Agent | null>(null);
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [currentConversation, setCurrentConversation] = useState<Conversation | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [inputValue, setInputValue] = useState<string>('');
  const [isStreaming, setIsStreaming] = useState<boolean>(false);
  const [searchFilter, setSearchFilter] = useState<string>('');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [editingTitleId, setEditingTitleId] = useState<string | null>(null);
  const [newTitle, setNewTitle] = useState<string>('');

  const abortControllerRef = useRef<AbortController | null>(null);
  const messagesEndRef = useRef<HTMLDivElement | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);

  // Suggested prompts per agent
  const suggestedPrompts: Record<string, string[]> = {
    research_agent: [
      "Research recent AI Agent Security vulnerabilities and mitigation best practices",
      "Explain the difference between direct prompt injection and indirect prompt injection",
      "What are the top 5 OWASP guidelines for Large Language Model applications?"
    ],
    file_agent: [
      "List the files I currently have uploaded in my workspace",
      "Explain how tenant resource isolation prevents cross-user file access",
      "Summarize the compliance requirements from uploaded security documentation"
    ],
    data_analysis_agent: [
      "Explain how statistical descriptive analysis detects dataset anomalies",
      "What checks are performed during schema validation for CSV uploads?",
      "How does the security gateway prevent arbitrary code execution in data analysis?"
    ],
    mail_agent: [
      "Draft an urgent security advisory email regarding suspicious tool activity",
      "Prepare a notification for stakeholders regarding scheduled gateway maintenance",
      "Draft an incident post-mortem email for the engineering team"
    ]
  };

  // 1. Load Agents
  useEffect(() => {
    api.getAgents().then((data) => {
      setAgents(data);
      const matched = data.find((a) => a.key === agentKeyParam) || data[0];
      if (matched) setCurrentAgent(matched);
    });
  }, [agentKeyParam]);

  // 2. Load Conversations for Selected Agent
  useEffect(() => {
    if (!currentAgent) return;
    loadConversations();
  }, [currentAgent]);

  const loadConversations = async () => {
    if (!currentAgent) return;
    try {
      const list = await api.getConversations(currentAgent.key);
      setConversations(list);
      if (list.length > 0) {
        loadConversationDetails(list[0].id);
      } else {
        setCurrentConversation(null);
        setMessages([]);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const loadConversationDetails = async (id: string) => {
    try {
      const conv = await api.getConversation(id);
      setCurrentConversation(conv);
      setMessages(conv.messages || []);
    } catch (e) {
      console.error(e);
    }
  };

  const handleStartNewConversation = async () => {
    if (!currentAgent) return;
    try {
      const newConv = await api.createConversation(currentAgent.key, `New ${currentAgent.name} Chat`);
      setConversations([newConv, ...conversations]);
      setCurrentConversation(newConv);
      setMessages([]);
      if (textareaRef.current) textareaRef.current.focus();
    } catch (e) {
      console.error(e);
    }
  };

  const handleSelectConversation = (conv: Conversation) => {
    if (currentConversation?.id === conv.id) return;
    loadConversationDetails(conv.id);
  };

  const handleDeleteConversation = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm('Are you sure you want to delete this conversation?')) return;
    try {
      await api.deleteConversation(id);
      const updated = conversations.filter((c) => c.id !== id);
      setConversations(updated);
      if (currentConversation?.id === id) {
        if (updated.length > 0) {
          loadConversationDetails(updated[0].id);
        } else {
          setCurrentConversation(null);
          setMessages([]);
        }
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleRenameConversation = async (id: string, e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) return;
    try {
      const updated = await api.renameConversation(id, newTitle.trim());
      setConversations(conversations.map((c) => (c.id === id ? updated : c)));
      if (currentConversation?.id === id) {
        setCurrentConversation(updated);
      }
      setEditingTitleId(null);
    } catch (err) {
      console.error(err);
    }
  };

  // Auto-scroll to bottom of messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isStreaming]);

  // Handle Send Message & Streaming
  const handleSendMessage = async (textToSend?: string) => {
    const text = (textToSend || inputValue).trim();
    if (!text || isStreaming || !currentAgent) return;

    let conv = currentConversation;
    if (!conv) {
      try {
        conv = await api.createConversation(currentAgent.key, text.slice(0, 30));
        setConversations([conv, ...conversations]);
        setCurrentConversation(conv);
      } catch (e) {
        console.error(e);
        return;
      }
    }

    // Add user message to UI immediately
    const userMsg: Message = {
      id: 'temp-' + Date.now(),
      conversation_id: conv.id,
      sender: 'user',
      content: text,
      tokens_used: 0,
      execution_status: 'COMPLETED',
      created_at: new Date().toISOString(),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputValue('');
    setIsStreaming(true);

    // Placeholder for streaming assistant response
    const assistantMsgId = 'stream-' + Date.now();
    const assistantMsg: Message = {
      id: assistantMsgId,
      conversation_id: conv.id,
      sender: 'assistant',
      content: '',
      model: currentAgent.name,
      tokens_used: 0,
      execution_status: 'RUNNING',
      created_at: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, assistantMsg]);

    const controller = new AbortController();
    abortControllerRef.current = controller;

    try {
      let accumulated = '';
      const stream = api.streamMessage(conv.id, text, controller.signal);

      for await (const { event, data } of stream) {
        if (event === 'chunk') {
          accumulated += data.text || '';
          setMessages((prev) =>
            prev.map((m) =>
              m.id === assistantMsgId ? { ...m, content: accumulated } : m
            )
          );
        } else if (event === 'security_block') {
          // Flagged by Central Security Gateway!
        } else if (event === 'done') {
          setMessages((prev) =>
            prev.map((m) =>
              m.id === assistantMsgId
                ? { ...m, execution_status: data.status || 'COMPLETED' }
                : m
            )
          );
        }
      }
    } catch (err: any) {
      if (err.name === 'AbortError') {
        setMessages((prev) =>
          prev.map((m) =>
            m.id === assistantMsgId
              ? { ...m, content: m.content + '\n\n*[Generation cancelled by user]*', execution_status: 'CANCELLED' }
              : m
          )
        );
      } else {
        setMessages((prev) =>
          prev.map((m) =>
            m.id === assistantMsgId
              ? { ...m, content: m.content + `\n\n⚠️ **Error:** ${err.message}`, execution_status: 'FAILED' }
              : m
          )
        );
      }
    } finally {
      setIsStreaming(false);
      abortControllerRef.current = null;
    }
  };

  const handleStopStreaming = () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
  };

  const handleCopy = (content: string, id: string) => {
    navigator.clipboard.writeText(content);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filteredConversations = conversations.filter((c) =>
    c.title.toLowerCase().includes(searchFilter.toLowerCase())
  );

  return (
    <div className="flex h-[calc(100vh-4rem)] overflow-hidden bg-slate-950">
      {/* ========================================================= */}
      {/* Sidebar: Conversation History & Agent Switcher */}
      {/* ========================================================= */}
      <div className="w-72 border-r border-slate-800/80 bg-slate-950/80 flex flex-col shrink-0">
        {/* Agent Selector Header */}
        <div className="p-4 border-b border-slate-800 space-y-3">
          <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
            Active Agent
          </div>
          <div className="relative">
            <select
              value={currentAgent?.key || ''}
              onChange={(e) => {
                const k = e.target.value;
                setSearchParams({ agent: k });
                const matched = agents.find((a) => a.key === k);
                if (matched) setCurrentAgent(matched);
              }}
              className="w-full bg-slate-900 border border-slate-700 rounded-xl px-3 py-2 text-xs font-semibold text-slate-200 appearance-none focus:outline-none focus:border-purple-500 cursor-pointer pr-8"
            >
              {agents.map((a) => (
                <option key={a.key} value={a.key}>
                  {a.name}
                </option>
              ))}
            </select>
            <ChevronDown className="w-4 h-4 text-slate-400 absolute right-2.5 top-2.5 pointer-events-none" />
          </div>

          {/* New Chat Button */}
          <button
            onClick={handleStartNewConversation}
            className="w-full py-2 px-3 rounded-xl bg-purple-600/30 hover:bg-purple-600/40 border border-purple-500/50 text-purple-200 text-xs font-semibold flex items-center justify-center space-x-2 transition-all shadow-sm"
          >
            <Plus className="w-4 h-4" />
            <span>New Chat Session</span>
          </button>
        </div>

        {/* Conversation Search Filter */}
        <div className="px-4 py-2 border-b border-slate-800/60">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search conversations..."
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              className="w-full bg-slate-900/60 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-300 placeholder-slate-500 focus:outline-none focus:border-purple-600"
            />
          </div>
        </div>

        {/* Conversations List */}
        <div className="flex-1 overflow-y-auto p-2 space-y-1">
          {filteredConversations.length === 0 ? (
            <div className="text-center py-8 text-slate-500 text-xs px-4">
              No conversations found for {currentAgent?.name}. Click "+ New Chat Session" to start.
            </div>
          ) : (
            filteredConversations.map((c) => {
              const isSelected = currentConversation?.id === c.id;
              const isEditing = editingTitleId === c.id;

              return (
                <div
                  key={c.id}
                  onClick={() => handleSelectConversation(c)}
                  className={`group px-3 py-2.5 rounded-xl text-xs cursor-pointer flex items-center justify-between transition-all ${
                    isSelected
                      ? 'bg-purple-950/60 border border-purple-700/50 text-white font-medium'
                      : 'text-slate-400 hover:bg-slate-900/70 hover:text-slate-200 border border-transparent'
                  }`}
                >
                  {isEditing ? (
                    <form
                      onSubmit={(e) => handleRenameConversation(c.id, e)}
                      onClick={(e) => e.stopPropagation()}
                      className="flex-1 mr-2"
                    >
                      <input
                        type="text"
                        autoFocus
                        value={newTitle}
                        onChange={(e) => setNewTitle(e.target.value)}
                        onBlur={() => setEditingTitleId(null)}
                        className="w-full bg-slate-900 border border-purple-500 rounded px-1.5 py-0.5 text-xs text-white focus:outline-none"
                      />
                    </form>
                  ) : (
                    <span className="truncate flex-1 mr-2">{c.title}</span>
                  )}

                  <div className="flex items-center space-x-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setEditingTitleId(c.id);
                        setNewTitle(c.title);
                      }}
                      title="Rename"
                      className="p-1 hover:text-purple-300"
                    >
                      <Edit2 className="w-3 h-3" />
                    </button>
                    <button
                      onClick={(e) => handleDeleteConversation(c.id, e)}
                      title="Delete"
                      className="p-1 hover:text-red-400"
                    >
                      <Trash2 className="w-3 h-3" />
                    </button>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* ========================================================= */}
      {/* Main Chat Area */}
      {/* ========================================================= */}
      <div className="flex-1 flex flex-col h-full overflow-hidden bg-slate-950 relative">
        {/* Top Chat Bar */}
        <div className="h-14 border-b border-slate-800/80 px-6 flex items-center justify-between bg-slate-950/40 backdrop-blur-md shrink-0">
          <div className="flex items-center space-x-3">
            <div className="p-1.5 rounded-lg bg-purple-950/80 border border-purple-600/40 text-purple-300">
              <Bot className="w-4 h-4" />
            </div>
            <div>
              <div className="text-xs font-bold text-white flex items-center space-x-2">
                <span>{currentAgent?.name}</span>
                <span className="text-[10px] font-mono text-purple-400 font-normal">
                  (Gateway Enforced)
                </span>
              </div>
              <div className="text-[10px] text-slate-400 truncate max-w-md">
                Allowed tools: {currentAgent?.allowed_tools.join(', ')}
              </div>
            </div>
          </div>

          <div className="flex items-center space-x-2 text-xs text-slate-400">
            <Shield className="w-3.5 h-3.5 text-emerald-400" />
            <span className="text-[11px] font-mono text-emerald-400">ZERO-TRUST VERIFIED</span>
          </div>
        </div>

        {/* Messages Container or Welcome Screen */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {messages.length === 0 ? (
            /* Gemini-Inspired Welcome Screen */
            <div className="max-w-2xl mx-auto py-12 flex flex-col items-center text-center space-y-6">
              <div className="p-4 rounded-3xl bg-gradient-to-tr from-purple-600/20 via-indigo-600/20 to-cyan-500/20 border border-purple-500/30 shadow-2xl gemini-glow">
                <Sparkles className="w-10 h-10 text-purple-400" />
              </div>

              <div>
                <h2 className="text-2xl font-extrabold text-white tracking-tight">
                  {currentAgent?.name}
                </h2>
                <p className="text-sm text-slate-400 mt-2 max-w-lg mx-auto leading-relaxed">
                  {currentAgent?.description}
                </p>
              </div>

              {/* Guardrails Pill */}
              <div className="flex items-center space-x-2 px-3 py-1.5 rounded-full bg-slate-900 border border-slate-800 text-xs text-slate-300">
                <Shield className="w-3.5 h-3.5 text-purple-400" />
                <span>Central Security Gateway Interception Enabled</span>
              </div>

              {/* Suggested Prompts */}
              <div className="w-full space-y-2 pt-4">
                <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider text-left">
                  Suggested Prompts
                </div>
                <div className="grid grid-cols-1 gap-2">
                  {suggestedPrompts[currentAgent?.key || 'research_agent']?.map((prompt, idx) => (
                    <button
                      key={idx}
                      onClick={() => handleSendMessage(prompt)}
                      className="p-3.5 text-left rounded-xl bg-slate-900/60 hover:bg-slate-900 border border-slate-800/80 hover:border-purple-500/40 text-xs text-slate-300 hover:text-white transition-all flex items-center justify-between group"
                    >
                      <span className="mr-2">{prompt}</span>
                      <Send className="w-3.5 h-3.5 text-slate-500 group-hover:text-purple-400 opacity-0 group-hover:opacity-100 transition-all shrink-0" />
                    </button>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            /* Conversation Messages */
            <div className="max-w-3xl mx-auto space-y-6">
              {messages.map((m) => {
                const isUser = m.sender === 'user';
                const isFailed = m.execution_status === 'FAILED';
                const isBlocked = m.execution_status === 'BLOCKED';

                return (
                  <div
                    key={m.id}
                    className={`flex items-start space-x-3.5 ${
                      isUser ? 'flex-row-reverse space-x-reverse' : ''
                    }`}
                  >
                    {/* Avatar */}
                    <div
                      className={`w-8 h-8 rounded-xl flex items-center justify-center shrink-0 text-xs font-bold shadow-md ${
                        isUser
                          ? 'bg-purple-600 text-white'
                          : isBlocked
                          ? 'bg-red-950 border border-red-500/60 text-red-300'
                          : 'bg-slate-900 border border-slate-800 text-purple-400'
                      }`}
                    >
                      {isUser ? <UserIcon className="w-4 h-4" /> : isBlocked ? <ShieldAlert className="w-4 h-4" /> : <Bot className="w-4 h-4" />}
                    </div>

                    {/* Bubble Content */}
                    <div
                      className={`relative group max-w-[85%] rounded-2xl px-5 py-3.5 text-sm leading-relaxed shadow-sm ${
                        isUser
                          ? 'bg-purple-600 text-white rounded-tr-sm'
                          : isBlocked
                          ? 'bg-red-950/40 border border-red-500/40 text-red-200 rounded-tl-sm'
                          : 'bg-slate-900/90 border border-slate-800 text-slate-200 rounded-tl-sm'
                      }`}
                    >
                      {/* Markdown Body */}
                      <div className="prose prose-invert prose-sm max-w-none break-words">
                        <ReactMarkdown remarkPlugins={[remarkGfm]}>
                          {m.content || (isStreaming ? 'Thinking...' : '')}
                        </ReactMarkdown>
                      </div>

                      {/* Message Footer / Copy */}
                      {!isUser && m.content && (
                        <div className="mt-2 pt-2 border-t border-slate-800/60 flex items-center justify-between text-[11px] text-slate-500">
                          <span className="font-mono text-[10px]">{m.model || 'Gemini'}</span>
                          <button
                            onClick={() => handleCopy(m.content, m.id)}
                            className="flex items-center space-x-1 text-slate-400 hover:text-slate-200 transition-colors"
                          >
                            {copiedId === m.id ? (
                              <>
                                <Check className="w-3 h-3 text-emerald-400" />
                                <span className="text-emerald-400">Copied</span>
                              </>
                            ) : (
                              <>
                                <Copy className="w-3 h-3" />
                                <span>Copy</span>
                              </>
                            )}
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
              <div ref={messagesEndRef} />
            </div>
          )}
        </div>

        {/* Message Composer */}
        <div className="p-4 border-t border-slate-800/80 bg-slate-950/80 backdrop-blur-md shrink-0">
          <div className="max-w-3xl mx-auto space-y-2">
            <div className="relative flex items-center bg-slate-900/90 border border-slate-700/80 rounded-2xl p-2 focus-within:border-purple-500 transition-all shadow-lg">
              <textarea
                ref={textareaRef}
                rows={1}
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    handleSendMessage();
                  }
                }}
                placeholder={`Ask ${currentAgent?.name || 'Agent'} anything... (Shift+Enter for new line)`}
                className="w-full bg-transparent px-3 py-1.5 text-sm text-slate-200 placeholder-slate-500 focus:outline-none resize-none max-h-32"
              />

              {isStreaming ? (
                <button
                  onClick={handleStopStreaming}
                  className="p-2 rounded-xl bg-red-600 hover:bg-red-500 text-white font-medium text-xs flex items-center space-x-1 shadow-md transition-colors"
                >
                  <Square className="w-3.5 h-3.5 fill-current" />
                  <span>Stop</span>
                </button>
              ) : (
                <button
                  disabled={!inputValue.trim()}
                  onClick={() => handleSendMessage()}
                  className="p-2 rounded-xl bg-purple-600 hover:bg-purple-500 disabled:opacity-40 disabled:cursor-not-allowed text-white shadow-md shadow-purple-950/50 transition-all"
                >
                  <Send className="w-4 h-4" />
                </button>
              )}
            </div>

            <div className="flex items-center justify-between text-[11px] text-slate-500 px-2 font-mono">
              <span>Enter to send · Shift+Enter for newline</span>
              <span className="flex items-center space-x-1 text-slate-400">
                <Shield className="w-3 h-3 text-purple-400" />
                <span>Central Security Gateway Interception Active</span>
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

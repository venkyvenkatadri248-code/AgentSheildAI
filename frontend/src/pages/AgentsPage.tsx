import React, { useEffect, useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Search,
  FileText,
  BarChart2,
  Mail,
  Bot,
  MessageSquare,
  Send,
  Sparkles,
  CheckCircle2,
  Shield,
  ShieldAlert,
  Lock,
  ArrowRight,
  Info,
  Plus,
  X,
  Loader2,
  Mic,
  Square,
  Copy,
  Check,
  Maximize2
} from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { api } from '../services/api';
import { Agent, Conversation, Message, UploadedFileItem } from '../types';

interface ChatbotMeta {
  displayName: string;
  role: string;
  tagline: string;
  themeColor: string;
  badgeClass: string;
  borderClass: string;
  glowClass: string;
  prompts: string[];
}

const CHATBOT_METAS: Record<string, ChatbotMeta> = {
  research_agent: {
    displayName: 'Research Bot',
    role: 'Research & Knowledge Assistant',
    tagline: 'Helps with topic research, academic papers, fact checking, and finding verified sources.',
    themeColor: 'text-cyan-400',
    badgeClass: 'border-cyan-500/40 bg-cyan-950/40 text-cyan-300',
    borderClass: 'border-cyan-500/30 hover:border-cyan-400/70',
    glowClass: 'shadow-cyan-950/30',
    prompts: [
      'What are the key concepts and latest trends in artificial intelligence?',
      'Explain the difference between direct prompt injection and indirect prompt injection',
      'Can you help research best practices for secure software development?'
    ]
  },
  file_agent: {
    displayName: 'Document Bot',
    role: 'Document & Writing Assistant',
    tagline: 'Assists with creating, reviewing, summarizing, and editing your documents and reports.',
    themeColor: 'text-purple-400',
    badgeClass: 'border-purple-500/40 bg-purple-950/40 text-purple-300',
    borderClass: 'border-purple-500/30 hover:border-purple-400/70',
    glowClass: 'shadow-purple-950/30',
    prompts: [
      'Can you help me draft a project overview and executive summary?',
      'Summarize the key takeaways and main points from my uploaded document',
      'What are effective techniques for editing and proofreading documentation?'
    ]
  },
  data_analysis_agent: {
    displayName: 'Data Analytics Bot',
    role: 'Data Analysis & Insights Assistant',
    tagline: 'Explores datasets, computes summary statistics, checks data quality, and explains trends.',
    themeColor: 'text-emerald-400',
    badgeClass: 'border-emerald-500/40 bg-emerald-950/40 text-emerald-300',
    borderClass: 'border-emerald-500/30 hover:border-emerald-400/70',
    glowClass: 'shadow-emerald-950/30',
    prompts: [
      'How do descriptive statistics help identify patterns and outliers in data?',
      'What are the best practices for handling missing values in a CSV dataset?',
      'Explain how standard deviation and variance measure distribution spread'
    ]
  },
  mail_agent: {
    displayName: 'Mail Bot',
    role: 'Email & Communication Assistant',
    tagline: 'Drafts clear, professional emails, summarizes message threads, and reviews correspondence.',
    themeColor: 'text-amber-400',
    badgeClass: 'border-amber-500/40 bg-amber-950/40 text-amber-300',
    borderClass: 'border-amber-500/30 hover:border-amber-400/70',
    glowClass: 'shadow-amber-950/30',
    prompts: [
      'Draft a polite and professional follow-up email regarding a project update',
      'Help compose a clear announcement email for team members about a new initiative',
      'Draft a professional meeting recap email with action items'
    ]
  }
};

export const AgentsPage: React.FC = () => {
  const navigate = useNavigate();
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Policy Modal state
  const [inspectAgent, setInspectAgent] = useState<Agent | null>(null);

  // Instant Chat Drawer State
  const [activeChatbot, setActiveChatbot] = useState<Agent | null>(null);
  const [drawerConversation, setDrawerConversation] = useState<Conversation | null>(null);
  const [drawerMessages, setDrawerMessages] = useState<Message[]>([]);
  const [drawerInput, setDrawerInput] = useState<string>('');
  const [drawerStreaming, setDrawerStreaming] = useState<boolean>(false);
  const [drawerCopiedId, setDrawerCopiedId] = useState<string | null>(null);

  // File & voice states for drawer
  const [drawerFiles, setDrawerFiles] = useState<UploadedFileItem[]>([]);
  const [drawerUploadingFile, setDrawerUploadingFile] = useState<boolean>(false);
  const [drawerListening, setDrawerListening] = useState<boolean>(false);

  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const recognitionRef = useRef<any>(null);
  const abortControllerRef = useRef<AbortController | null>(null);
  const messagesEndRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    api.getAgents()
      .then(setAgents)
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [drawerMessages, drawerStreaming]);

  const getAgentMeta = (key: string): ChatbotMeta => {
    return CHATBOT_METAS[key] || {
      displayName: 'AI Bot',
      role: 'Autonomous Assistant',
      tagline: 'Specialized conversational AI agent with real-time zero-trust security guardrails.',
      themeColor: 'text-purple-400',
      badgeClass: 'border-purple-500/40 bg-purple-950/40 text-purple-300',
      borderClass: 'border-purple-500/30 hover:border-purple-400/70',
      glowClass: 'shadow-purple-950/30',
      prompts: ['What can you help me with today?']
    };
  };

  const getAgentIcon = (iconName: string, themeColor: string) => {
    switch (iconName.toLowerCase()) {
      case 'search':
        return <Search className={`w-6 h-6 ${themeColor}`} />;
      case 'filetext':
      case 'file-text':
        return <FileText className={`w-6 h-6 ${themeColor}`} />;
      case 'barchart2':
      case 'bar-chart-2':
        return <BarChart2 className={`w-6 h-6 ${themeColor}`} />;
      case 'mail':
        return <Mail className={`w-6 h-6 ${themeColor}`} />;
      default:
        return <Bot className={`w-6 h-6 ${themeColor}`} />;
    }
  };

  // Open the instant chatbot modal/drawer
  const handleOpenChatDrawer = async (agent: Agent, initialPrompt?: string) => {
    setActiveChatbot(agent);
    setDrawerMessages([]);
    setDrawerInput('');
    setDrawerFiles([]);
    setDrawerStreaming(false);

    try {
      const convList = await api.getConversations(agent.key);
      let conv: Conversation;
      if (convList.length > 0) {
        conv = await api.getConversation(convList[0].id);
        setDrawerConversation(conv);
        setDrawerMessages(conv.messages || []);
      } else {
        conv = await api.createConversation(agent.key, `Chat with ${getAgentMeta(agent.key).displayName}`);
        setDrawerConversation(conv);
        setDrawerMessages([]);
      }

      if (initialPrompt) {
        setTimeout(() => {
          handleSendDrawerMessage(initialPrompt, agent, conv);
        }, 100);
      }
    } catch (e) {
      console.error('Error starting conversation:', e);
    }
  };

  const handleCloseChatDrawer = () => {
    if (drawerStreaming && abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    if (drawerListening && recognitionRef.current) {
      recognitionRef.current.stop();
    }
    setActiveChatbot(null);
    setDrawerConversation(null);
    setDrawerMessages([]);
  };

  const handleSendDrawerMessage = async (
    textToSend?: string,
    targetAgent?: Agent,
    targetConv?: Conversation
  ) => {
    const text = (textToSend || drawerInput).trim();
    const currentBot = targetAgent || activeChatbot;
    if (!text || drawerStreaming || !currentBot) return;

    if (drawerListening && recognitionRef.current) {
      recognitionRef.current.stop();
      setDrawerListening(false);
    }

    let conv = targetConv || drawerConversation;
    if (!conv) {
      try {
        conv = await api.createConversation(currentBot.key, text.slice(0, 30));
        setDrawerConversation(conv);
      } catch (e) {
        console.error(e);
        return;
      }
    }

    const currentFiles = [...drawerFiles];
    let payloadText = text;
    if (currentFiles.length > 0) {
      const docsContext = currentFiles
        .map(
          (f) =>
            `[Attached Document: "${f.original_name}"]\n${
              f.extracted_text_preview ? `Preview:\n"""\n${f.extracted_text_preview}\n"""\n` : ''
            }`
        )
        .join('\n\n');
      payloadText = `${payloadText}\n\n--- User Documents Context ---\n${docsContext}`;
    }

    const userMessage: Message = {
      id: `usr_${Date.now()}`,
      conversation_id: conv.id,
      sender: 'user',
      content: text,
      tokens_used: 0,
      execution_status: 'SUCCESS',
      created_at: new Date().toISOString()
    };

    const assistantMsgId = `ast_${Date.now()}`;
    const assistantMessage: Message = {
      id: assistantMsgId,
      conversation_id: conv.id,
      sender: 'assistant',
      content: '',
      model: 'Central Security Gateway',
      tokens_used: 0,
      execution_status: 'RUNNING',
      created_at: new Date().toISOString()
    };

    setDrawerMessages((prev) => [...prev, userMessage, assistantMessage]);
    setDrawerInput('');
    setDrawerFiles([]);
    setDrawerStreaming(true);

    const abortController = new AbortController();
    abortControllerRef.current = abortController;

    try {
      let accumulated = '';
      for await (const chunk of api.streamMessage(conv.id, payloadText, abortController.signal)) {
        const { event, data } = chunk;
        if (event === 'chunk' && data.text) {
          accumulated += data.text;
          setDrawerMessages((prev) =>
            prev.map((m) =>
              m.id === assistantMsgId ? { ...m, content: accumulated } : m
            )
          );
        } else if (event === 'done') {
          setDrawerMessages((prev) =>
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
        setDrawerMessages((prev) =>
          prev.map((m) =>
            m.id === assistantMsgId
              ? { ...m, content: m.content + '\n\n*[Stopped by user]*', execution_status: 'CANCELLED' }
              : m
          )
        );
      } else {
        setDrawerMessages((prev) =>
          prev.map((m) =>
            m.id === assistantMsgId
              ? { ...m, content: m.content + `\n\n⚠️ **Error:** ${err.message}`, execution_status: 'FAILED' }
              : m
          )
        );
      }
    } finally {
      setDrawerStreaming(false);
      abortControllerRef.current = null;
    }
  };

  const handleCopy = (content: string, id: string) => {
    navigator.clipboard.writeText(content);
    setDrawerCopiedId(id);
    setTimeout(() => setDrawerCopiedId(null), 2000);
  };

  const filteredAgents = agents.filter((agent) => {
    const meta = getAgentMeta(agent.key);
    const matchesCategory = selectedCategory === 'all' || agent.key === selectedCategory;
    const matchesSearch =
      agent.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      meta.displayName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      meta.role.toLowerCase().includes(searchQuery.toLowerCase()) ||
      agent.description.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesCategory && matchesSearch;
  });

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex items-center space-x-3 mb-2">
            <div className="p-2 rounded-xl bg-purple-950/80 border border-purple-600/40 text-purple-300 shadow-md shadow-purple-950">
              <Bot className="w-6 h-6 text-purple-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white flex items-center space-x-2.5">
                <span>My Agents</span>
                <span className="text-xs font-mono font-semibold px-2.5 py-0.5 rounded-full bg-emerald-950 text-emerald-300 border border-emerald-800/50 flex items-center space-x-1.5">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                  <span>4 ACTIVE AGENTS</span>
                </span>
              </h1>
              <p className="text-sm text-slate-400 mt-1">
                Specialized conversational agents with isolated operational toolsets and strict runtime security policies.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={() => navigate('/chat')}
            className="py-2.5 px-4 rounded-xl bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white text-xs font-semibold flex items-center space-x-2 shadow-lg shadow-purple-950/50 transition-all cursor-pointer"
          >
            <MessageSquare className="w-4 h-4" />
            <span>Open Chat</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Filter and Search Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        {/* Category Pills */}
        <div className="flex items-center space-x-2 overflow-x-auto pb-1 sm:pb-0">
          <button
            onClick={() => setSelectedCategory('all')}
            className={`px-3.5 py-1.5 rounded-xl text-xs font-medium transition-all cursor-pointer ${
              selectedCategory === 'all'
                ? 'bg-purple-600 text-white shadow-md shadow-purple-950'
                : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
            }`}
          >
            All Agents ({agents.length})
          </button>
          {agents.map((agent) => {
            const meta = getAgentMeta(agent.key);
            const isSelected = selectedCategory === agent.key;
            return (
              <button
                key={agent.id}
                onClick={() => setSelectedCategory(agent.key)}
                className={`px-3.5 py-1.5 rounded-xl text-xs font-medium whitespace-nowrap transition-all cursor-pointer ${
                  isSelected
                    ? 'bg-purple-600 text-white shadow-md shadow-purple-950'
                    : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
                }`}
              >
                {meta.displayName}
              </button>
            );
          })}
        </div>

        {/* Search input */}
        <div className="relative w-full sm:w-64">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search chatbots..."
            className="w-full bg-slate-900 border border-slate-800 text-xs rounded-xl pl-9 pr-3 py-2 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500 transition-colors"
          />
        </div>
      </div>

      {/* Chatbots Roster Grid */}
      {loading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-80 rounded-2xl bg-slate-900/50 border border-slate-800 animate-pulse" />
          ))}
        </div>
      ) : filteredAgents.length === 0 ? (
        <div className="p-12 text-center rounded-2xl border border-dashed border-slate-800 text-slate-400 text-sm">
          No chatbots found matching your search.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {filteredAgents.map((agent) => {
            const meta = getAgentMeta(agent.key);

            return (
              <div
                key={agent.id}
                className={`p-6 rounded-2xl border ${meta.borderClass} bg-slate-950/70 backdrop-blur-md flex flex-col justify-between shadow-xl ${meta.glowClass} transition-all duration-300 group`}
              >
                <div>
                  {/* Top Bar: Avatar & Title */}
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex items-center space-x-3.5">
                      <div className="p-3.5 rounded-2xl bg-slate-900 border border-slate-800 shadow-inner group-hover:scale-105 transition-transform">
                        {getAgentIcon(agent.icon, meta.themeColor)}
                      </div>
                      <div>
                        <div className="flex items-center space-x-2">
                          <h3 className="text-lg font-bold text-white group-hover:text-purple-300 transition-colors">
                            {meta.displayName}
                          </h3>
                          <span className={`inline-block text-[10px] font-mono px-2 py-0.5 rounded border ${meta.badgeClass}`}>
                            {agent.key}
                          </span>
                        </div>
                        <p className="text-xs text-slate-400 font-medium mt-0.5">
                          {meta.role}
                        </p>
                      </div>
                    </div>

                    {/* Online status indicator */}
                    <div className="flex items-center space-x-1.5 text-xs text-emerald-400 font-medium bg-emerald-950/40 border border-emerald-800/40 px-2.5 py-1 rounded-full">
                      <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                      <span>Online</span>
                    </div>
                  </div>

                  {/* Tagline / Bio */}
                  <p className="text-xs text-slate-300 leading-relaxed mb-4">
                    {meta.tagline}
                  </p>

                  {/* Permitted Tools */}
                  <div className="space-y-1.5 mb-5">
                    <div className="text-[11px] font-semibold text-slate-400 flex items-center space-x-1.5">
                      <Lock className="w-3 h-3 text-slate-500" />
                      <span>Authorized Toolset</span>
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {agent.allowed_tools && agent.allowed_tools.length > 0 ? (
                        agent.allowed_tools.map((t) => (
                          <span
                            key={t}
                            className="px-2 py-0.5 text-[11px] font-mono rounded-md bg-slate-900/90 border border-slate-800 text-slate-300"
                          >
                            {t}
                          </span>
                        ))
                      ) : (
                        <span className="text-xs text-slate-500 italic">No tools assigned</span>
                      )}
                    </div>
                  </div>

                  {/* Clickable Starter Prompts */}
                  <div className="space-y-2 mb-6">
                    <div className="text-[11px] font-semibold text-slate-400 flex items-center space-x-1.5">
                      <Sparkles className="w-3 h-3 text-purple-400" />
                      <span>Suggested Starter Prompts (Click to chat)</span>
                    </div>
                    <div className="space-y-1.5">
                      {meta.prompts.map((prompt, idx) => (
                        <button
                          key={idx}
                          onClick={() => handleOpenChatDrawer(agent, prompt)}
                          className="w-full text-left p-2.5 rounded-xl bg-slate-900/70 hover:bg-slate-900 border border-slate-800/90 hover:border-purple-500/50 text-[11px] text-slate-300 hover:text-white transition-all flex items-center justify-between group/prompt cursor-pointer"
                        >
                          <span className="truncate mr-2 font-normal">"{prompt}"</span>
                          <Send className="w-3 h-3 text-slate-500 group-hover/prompt:text-purple-400 opacity-60 group-hover/prompt:opacity-100 shrink-0 transition-opacity" />
                        </button>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Primary Actions Bar */}
                <div className="flex items-center space-x-2 pt-4 border-t border-slate-900">
                  <button
                    onClick={() => setInspectAgent(agent)}
                    title="View security policies and guardrails"
                    className="p-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700/80 text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
                  >
                    <Info className="w-4 h-4 text-purple-400" />
                  </button>

                  <button
                    onClick={() => handleOpenChatDrawer(agent)}
                    className="flex-1 py-2.5 px-3 rounded-xl bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white text-xs font-semibold flex items-center justify-center space-x-2 shadow-md shadow-purple-950/40 transition-all cursor-pointer"
                  >
                    <MessageSquare className="w-3.5 h-3.5" />
                    <span>Chat with {meta.displayName}</span>
                  </button>

                  <button
                    onClick={() => navigate(`/chat?agent=${agent.key}`)}
                    title="Open in full chat workspace"
                    className="py-2.5 px-3 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700/80 text-slate-300 hover:text-white text-xs font-medium flex items-center space-x-1.5 transition-colors cursor-pointer"
                  >
                    <span>Full View</span>
                    <ArrowRight className="w-3.5 h-3.5 text-slate-400" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* ========================================================= */}
      {/* INSTANT CHATBOT DRAWER / MODAL                            */}
      {/* ========================================================= */}
      {activeChatbot && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-md p-4 sm:p-6 animate-fadeIn">
          <div className="w-full max-w-3xl h-[85vh] bg-slate-950 border border-purple-500/40 rounded-2xl shadow-2xl flex flex-col overflow-hidden">
            {/* Drawer Header */}
            <div className="h-14 border-b border-slate-800/80 px-5 flex items-center justify-between bg-slate-900/60 shrink-0">
              <div className="flex items-center space-x-3">
                <div className="p-2 rounded-xl bg-slate-900 border border-slate-800">
                  {getAgentIcon(activeChatbot.icon, getAgentMeta(activeChatbot.key).themeColor)}
                </div>
                <div>
                  <div className="text-sm font-bold text-white flex items-center space-x-2">
                    <span>{getAgentMeta(activeChatbot.key).displayName}</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-800/40 flex items-center space-x-1">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                      <span>Online</span>
                    </span>
                  </div>
                  <div className="text-[10px] text-slate-400 truncate max-w-sm">
                    {getAgentMeta(activeChatbot.key).role}
                  </div>
                </div>
              </div>

              <div className="flex items-center space-x-2">
                <button
                  onClick={() => {
                    const k = activeChatbot.key;
                    handleCloseChatDrawer();
                    navigate(`/chat?agent=${k}`);
                  }}
                  title="Open in Full Chatroom"
                  className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors cursor-pointer"
                >
                  <Maximize2 className="w-4 h-4" />
                </button>
                <button
                  onClick={handleCloseChatDrawer}
                  title="Close Chat"
                  className="p-1.5 rounded-lg bg-slate-800 hover:bg-red-900/40 text-slate-400 hover:text-red-300 transition-colors cursor-pointer text-lg leading-none"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Drawer Messages Area */}
            <div className="flex-1 overflow-y-auto p-5 space-y-4 bg-slate-950/80">
              {drawerMessages.length === 0 ? (
                <div className="py-12 flex flex-col items-center text-center space-y-4 max-w-md mx-auto">
                  <div className="p-4 rounded-2xl bg-purple-950/40 border border-purple-500/30 text-purple-300">
                    <Bot className="w-8 h-8" />
                  </div>
                  <h3 className="text-lg font-bold text-white">
                    Chat with {getAgentMeta(activeChatbot.key).displayName}
                  </h3>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    {getAgentMeta(activeChatbot.key).tagline}
                  </p>

                  <div className="w-full pt-4 space-y-2">
                    <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider text-left">
                      Suggested Questions
                    </div>
                    {getAgentMeta(activeChatbot.key).prompts.map((p, i) => (
                      <button
                        key={i}
                        onClick={() => handleSendDrawerMessage(p)}
                        className="w-full text-left p-2.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-purple-500/50 text-xs text-slate-300 hover:text-white transition-all flex items-center justify-between cursor-pointer"
                      >
                        <span className="truncate mr-2">"{p}"</span>
                        <Send className="w-3 h-3 text-slate-500 shrink-0" />
                      </button>
                    ))}
                  </div>
                </div>
              ) : (
                drawerMessages.map((m) => {
                  const isUser = m.sender === 'user';
                  const isBlocked = m.execution_status === 'BLOCKED';

                  return (
                    <div
                      key={m.id}
                      className={`flex items-start space-x-3 ${
                        isUser ? 'flex-row-reverse space-x-reverse' : ''
                      }`}
                    >
                      <div
                        className={`w-7 h-7 rounded-xl flex items-center justify-center shrink-0 text-xs font-bold shadow-md ${
                          isUser
                            ? 'bg-purple-600 text-white'
                            : isBlocked
                            ? 'bg-red-950 border border-red-500/60 text-red-300'
                            : 'bg-slate-900 border border-slate-800 text-purple-400'
                        }`}
                      >
                        {isUser ? <Bot className="w-3.5 h-3.5" /> : isBlocked ? <ShieldAlert className="w-3.5 h-3.5" /> : <Bot className="w-3.5 h-3.5" />}
                      </div>

                      <div
                        className={`max-w-[85%] rounded-2xl px-4 py-3 text-xs leading-relaxed shadow-sm ${
                          isUser
                            ? 'bg-purple-600 text-white rounded-tr-sm'
                            : isBlocked
                            ? 'bg-red-950/40 border border-red-500/40 text-red-200 rounded-tl-sm'
                            : 'bg-slate-900/90 border border-slate-800 text-slate-200 rounded-tl-sm'
                        }`}
                      >
                        <div className="prose prose-invert prose-xs max-w-none break-words">
                          <ReactMarkdown remarkPlugins={[remarkGfm]}>
                            {m.content || (drawerStreaming ? 'Thinking...' : '')}
                          </ReactMarkdown>
                        </div>

                        {!isUser && m.content && (
                          <div className="mt-2 pt-2 border-t border-slate-800/60 flex items-center justify-between text-[10px] text-slate-500">
                            <span className="font-mono">{getAgentMeta(activeChatbot.key).displayName}</span>
                            <button
                              onClick={() => handleCopy(m.content, m.id)}
                              className="flex items-center space-x-1 text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
                            >
                              {drawerCopiedId === m.id ? (
                                <>
                                  <Check className="w-2.5 h-2.5 text-emerald-400" />
                                  <span className="text-emerald-400">Copied</span>
                                </>
                              ) : (
                                <>
                                  <Copy className="w-2.5 h-2.5" />
                                  <span>Copy</span>
                                </>
                              )}
                            </button>
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })
              )}
              <div ref={messagesEndRef} />
            </div>

            {/* Drawer Input Composer */}
            <div className="p-3.5 border-t border-slate-800/80 bg-slate-900/80 backdrop-blur-md shrink-0">
              <div className="space-y-2">
                <div className="relative flex items-center bg-slate-900 border border-slate-700/80 focus-within:border-purple-500 rounded-full pl-3 pr-2 py-1.5 shadow-lg">
                  <textarea
                    rows={1}
                    value={drawerInput}
                    onChange={(e) => setDrawerInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' && !e.shiftKey) {
                        e.preventDefault();
                        handleSendDrawerMessage();
                      }
                    }}
                    placeholder={`Message ${getAgentMeta(activeChatbot.key).displayName}...`}
                    className="flex-1 bg-transparent px-3 py-1 text-xs text-slate-100 placeholder-slate-400 focus:outline-none resize-none leading-relaxed"
                  />

                  {drawerStreaming ? (
                    <button
                      onClick={() => abortControllerRef.current?.abort()}
                      className="p-1.5 rounded-full bg-red-600 text-white cursor-pointer"
                    >
                      <Square className="w-3.5 h-3.5 fill-current" />
                    </button>
                  ) : (
                    <button
                      onClick={() => handleSendDrawerMessage()}
                      disabled={!drawerInput.trim()}
                      className="p-1.5 rounded-full bg-purple-600 hover:bg-purple-500 disabled:opacity-40 text-white cursor-pointer transition-all"
                    >
                      <Send className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>

                <div className="flex items-center justify-between text-[10px] text-slate-500 px-3">
                  <span>Enter to send · Shift+Enter for newline</span>
                  <button
                    onClick={() => {
                      const k = activeChatbot.key;
                      handleCloseChatDrawer();
                      navigate(`/chat?agent=${k}`);
                    }}
                    className="text-purple-400 hover:text-purple-300 font-medium underline"
                  >
                    Open full chat workspace &rarr;
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================= */}
      {/* AGENT POLICY DETAIL MODAL                                 */}
      {/* ========================================================= */}
      {inspectAgent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 animate-fadeIn">
          <div className="w-full max-w-lg bg-slate-950 border border-slate-800 rounded-2xl p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Shield className="w-5 h-5 text-purple-400" />
                <h3 className="font-bold text-white text-base">
                  {getAgentMeta(inspectAgent.key).displayName} Security Guardrails
                </h3>
              </div>
              <button
                onClick={() => setInspectAgent(null)}
                className="text-slate-400 hover:text-white text-lg leading-none cursor-pointer"
              >
                &times;
              </button>
            </div>

            <div className="space-y-3 text-xs text-slate-300">
              <div>
                <span className="font-semibold text-slate-400 block mb-1">Chatbot Profile:</span>
                <code className="text-purple-300 font-mono bg-slate-900 px-2 py-1 rounded">
                  {inspectAgent.key}
                </code>
              </div>
              <div>
                <span className="font-semibold text-slate-400 block mb-1">Enforced Guardrails:</span>
                <ul className="list-disc pl-5 space-y-1 text-slate-400">
                  <li>Mandatory argument schema validation before tool dispatch</li>
                  <li>Indirect prompt injection sanitization on external payloads</li>
                  <li>Zero-trust resource ownership verification</li>
                  {inspectAgent.key === 'mail_agent' && (
                    <li className="text-amber-300 font-medium">Human-in-the-loop approval gated for outbound email dispatch</li>
                  )}
                </ul>
              </div>
              <div>
                <span className="font-semibold text-slate-400 block mb-1">Permitted Tool Call Whitelist:</span>
                <div className="flex flex-wrap gap-1">
                  {inspectAgent.allowed_tools.map((t) => (
                    <span key={t} className="px-2 py-0.5 font-mono text-[11px] rounded bg-purple-950/60 border border-purple-800/60 text-purple-300">
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-end space-x-2">
              <button
                onClick={() => setInspectAgent(null)}
                className="px-4 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-xl text-xs font-medium text-slate-300 cursor-pointer"
              >
                Close
              </button>
              <button
                onClick={() => {
                  const target = inspectAgent;
                  setInspectAgent(null);
                  handleOpenChatDrawer(target);
                }}
                className="px-4 py-1.5 bg-purple-600 hover:bg-purple-500 rounded-xl text-xs font-semibold text-white cursor-pointer"
              >
                Chat with Bot
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

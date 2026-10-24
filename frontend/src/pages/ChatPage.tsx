import React, { useState, useEffect, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Send,
  Square,
  Bot,
  User as UserIcon,
  Plus,
  Copy,
  Check,
  Shield,
  ShieldAlert,
  Sparkles,
  ChevronDown,
  Mic,
  FileText,
  X,
  Loader2,
  Search,
  BarChart2,
  Mail
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
  accentBg: string;
  borderAccent: string;
  badgeClass: string;
  prompts: string[];
}

const CHATBOT_METAS: Record<string, ChatbotMeta> = {
  research_agent: {
    displayName: 'Research Bot',
    role: 'Research & Knowledge Assistant',
    tagline: 'Helps with topic research, academic papers, fact checking, and finding verified sources.',
    themeColor: 'text-cyan-400',
    accentBg: 'bg-cyan-950/40',
    borderAccent: 'border-cyan-500/40 hover:border-cyan-400',
    badgeClass: 'border-cyan-500/40 bg-cyan-950/40 text-cyan-300',
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
    accentBg: 'bg-purple-950/40',
    borderAccent: 'border-purple-500/40 hover:border-purple-400',
    badgeClass: 'border-purple-500/40 bg-purple-950/40 text-purple-300',
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
    accentBg: 'bg-emerald-950/40',
    borderAccent: 'border-emerald-500/40 hover:border-emerald-400',
    badgeClass: 'border-emerald-500/40 bg-emerald-950/40 text-emerald-300',
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
    accentBg: 'bg-amber-950/40',
    borderAccent: 'border-amber-500/40 hover:border-amber-400',
    badgeClass: 'border-amber-500/40 bg-amber-950/40 text-amber-300',
    prompts: [
      'Draft a polite and professional follow-up email regarding a project update',
      'Help compose a clear announcement email for team members about a new initiative',
      'Draft a professional meeting recap email with action items'
    ]
  }
};

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
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // File upload & Mic speech recognition states
  const [attachedFiles, setAttachedFiles] = useState<UploadedFileItem[]>([]);
  const [isUploadingFile, setIsUploadingFile] = useState<boolean>(false);
  const [fileUploadError, setFileUploadError] = useState<string | null>(null);
  const [isListening, setIsListening] = useState<boolean>(false);

  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const recognitionRef = useRef<any>(null);
  const abortControllerRef = useRef<AbortController | null>(null);
  const messagesEndRef = useRef<HTMLDivElement | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);

  const getAgentMeta = (key?: string): ChatbotMeta => {
    return CHATBOT_METAS[key || 'research_agent'] || {
      displayName: 'AI Bot',
      role: 'Autonomous Assistant',
      tagline: 'Specialized conversational AI agent with real-time zero-trust security guardrails.',
      themeColor: 'text-purple-400',
      accentBg: 'bg-purple-950/40',
      borderAccent: 'border-purple-500/30 hover:border-purple-400/70',
      badgeClass: 'border-purple-500/40 bg-purple-950/40 text-purple-300',
      prompts: ['What can you help me with today?']
    };
  };

  const getAgentIcon = (key: string, size = 'w-4 h-4') => {
    switch (key) {
      case 'research_agent':
        return <Search className={`${size} text-cyan-400`} />;
      case 'file_agent':
        return <FileText className={`${size} text-purple-400`} />;
      case 'data_analysis_agent':
        return <BarChart2 className={`${size} text-emerald-400`} />;
      case 'mail_agent':
        return <Mail className={`${size} text-amber-400`} />;
      default:
        return <Bot className={`${size} text-purple-400`} />;
    }
  };

  // 1. Load Agents
  useEffect(() => {
    api.getAgents().then((data) => {
      setAgents(data);
      const matched = data.find((a) => a.key === agentKeyParam) || data[0];
      if (matched) setCurrentAgent(matched);
    });
  }, [agentKeyParam]);

  // 2. Load Recent Conversations for Current Agent
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

  const handleSelectAgent = (agent: Agent) => {
    if (currentAgent?.key === agent.key) return;
    setSearchParams({ agent: agent.key });
    setCurrentAgent(agent);
    setCurrentConversation(null);
    setMessages([]);
    setAttachedFiles([]);
    setInputValue('');
  };

  const handleStartNewConversation = async () => {
    if (!currentAgent) return;
    try {
      const meta = getAgentMeta(currentAgent.key);
      const newConv = await api.createConversation(currentAgent.key, `Chat with ${meta.displayName}`);
      setCurrentConversation(newConv);
      setMessages([]);
      setConversations((prev) => [newConv, ...prev]);
      if (textareaRef.current) textareaRef.current.focus();
    } catch (e) {
      console.error(e);
      setCurrentConversation(null);
      setMessages([]);
    }
  };

  // Auto-scroll to bottom of messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isStreaming]);

  // File Attachment Handlers
  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    e.target.value = '';

    setIsUploadingFile(true);
    setFileUploadError(null);

    try {
      const uploaded = await api.uploadFile(file);
      setAttachedFiles((prev) => [...prev, uploaded]);
    } catch (err: any) {
      console.error('File upload error:', err);
      setFileUploadError(err.message || 'Failed to upload file');
      setTimeout(() => setFileUploadError(null), 5000);
    } finally {
      setIsUploadingFile(false);
    }
  };

  const handleRemoveFile = (id: string) => {
    setAttachedFiles((prev) => prev.filter((f) => f.id !== id));
  };

  // Mic Speech Recognition Handler (Web Speech API)
  const toggleListening = () => {
    if (isListening) {
      if (recognitionRef.current) {
        recognitionRef.current.stop();
      }
      setIsListening(false);
      return;
    }

    const SpeechRecognition =
      (window as any).SpeechRecognition || (window as any).webkitSpeechRecognition;

    if (!SpeechRecognition) {
      alert(
        'Speech recognition is not supported in this browser. Please use Google Chrome, Microsoft Edge, or a supported browser with microphone permissions.'
      );
      return;
    }

    try {
      const recognition = new SpeechRecognition();
      recognition.continuous = true;
      recognition.interimResults = true;
      recognition.lang = 'en-US';

      recognition.onstart = () => {
        setIsListening(true);
      };

      recognition.onresult = (event: any) => {
        let transcript = '';
        for (let i = event.resultIndex; i < event.results.length; i++) {
          transcript += event.results[i][0].transcript;
        }
        if (transcript) {
          setInputValue((prev) => {
            const trimmed = prev.trim();
            return trimmed ? `${trimmed} ${transcript}` : transcript;
          });
        }
      };

      recognition.onerror = (event: any) => {
        console.warn('Speech recognition error:', event.error);
        setIsListening(false);
      };

      recognition.onend = () => {
        setIsListening(false);
      };

      recognitionRef.current = recognition;
      recognition.start();
    } catch (err) {
      console.error('Failed to start speech recognition:', err);
      setIsListening(false);
    }
  };

  // Handle Send Message & Streaming
  const handleSendMessage = async (textToSend?: string) => {
    const text = (textToSend || inputValue).trim();
    if (!text || isStreaming || !currentAgent) return;

    if (isListening && recognitionRef.current) {
      recognitionRef.current.stop();
      setIsListening(false);
    }

    let conv = currentConversation;
    if (!conv) {
      try {
        conv = await api.createConversation(currentAgent.key, text.slice(0, 30));
        setCurrentConversation(conv);
        setConversations((prev) => [conv!, ...prev]);
      } catch (e) {
        console.error(e);
        return;
      }
    }

    const currentFiles = [...attachedFiles];
    let payloadText = text;
    if (currentFiles.length > 0) {
      const docsContext = currentFiles
        .map(
          (f) =>
            `[Attached Document: "${f.original_name}"]\n${
              f.extracted_text_preview ? `Content Preview / Extracted Text:\n"""\n${f.extracted_text_preview}\n"""\n` : ''
            }`
        )
        .join('\n\n');
      payloadText = `${docsContext}\n\nUser Question: ${text}`;
      setAttachedFiles([]);
    }

    const userDisplayContent = currentFiles.length > 0
      ? `${currentFiles.map((f) => `📎 **${f.original_name}**`).join(' · ')}\n\n${text}`
      : text;

    const userMsg: Message = {
      id: 'temp-' + Date.now(),
      conversation_id: conv.id,
      sender: 'user',
      content: userDisplayContent,
      tokens_used: 0,
      execution_status: 'COMPLETED',
      created_at: new Date().toISOString(),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputValue('');
    setIsStreaming(true);

    const meta = getAgentMeta(currentAgent.key);
    const assistantMsgId = 'stream-' + Date.now();
    const assistantMsg: Message = {
      id: assistantMsgId,
      conversation_id: conv.id,
      sender: 'assistant',
      content: '',
      model: meta.displayName,
      tokens_used: 0,
      execution_status: 'RUNNING',
      created_at: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, assistantMsg]);

    const controller = new AbortController();
    abortControllerRef.current = controller;

    try {
      let accumulated = '';
      const stream = api.streamMessage(conv.id, payloadText, controller.signal);

      for await (const { event, data } of stream) {
        if (event === 'chunk') {
          accumulated += data.text || '';
          setMessages((prev) =>
            prev.map((m) =>
              m.id === assistantMsgId ? { ...m, content: accumulated } : m
            )
          );
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
              ? { ...m, content: m.content + '\n\n*[Generation stopped by user]*', execution_status: 'CANCELLED' }
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

  const activeMeta = getAgentMeta(currentAgent?.key);

  return (
    <div className="flex h-[calc(100vh-4rem)] overflow-hidden bg-slate-950">
      {/* ========================================================= */}
      {/* MAIN CHAT AREA                                            */}
      {/* ========================================================= */}
      <div className="flex-1 flex flex-col h-full overflow-hidden bg-slate-950 relative">
        {/* Top Chat Bar */}
        <div className="h-14 border-b border-slate-800/80 px-4 sm:px-6 flex items-center justify-between bg-slate-950/60 backdrop-blur-md shrink-0">
          <div className="flex items-center space-x-3">
            <div className="p-1.5 rounded-xl bg-purple-950/80 border border-purple-600/40 shadow-sm shadow-purple-950">
              {currentAgent && getAgentIcon(currentAgent.key, 'w-4 h-4')}
            </div>

            <div>
              <div className="text-xs font-bold text-white flex items-center space-x-2">
                <span>{activeMeta.displayName}</span>
                <span className="text-[10px] font-mono text-emerald-400 px-1.5 py-0.2 rounded bg-emerald-950/60 border border-emerald-800/40 flex items-center space-x-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  <span>Online</span>
                </span>
              </div>
              <div className="text-[10px] text-slate-400 truncate max-w-xs sm:max-w-md hidden sm:block">
                {activeMeta.role}
              </div>
            </div>
          </div>

          {/* Quick Chatbot Switcher Pills (Top Header) */}
          <div className="hidden lg:flex items-center space-x-1.5 bg-slate-900/80 border border-slate-800 p-1 rounded-xl">
            {agents.map((a) => {
              const meta = getAgentMeta(a.key);
              const isSelected = currentAgent?.key === a.key;
              return (
                <button
                  key={a.key}
                  onClick={() => handleSelectAgent(a)}
                  className={`px-2.5 py-1 rounded-lg text-[11px] font-medium transition-all flex items-center space-x-1.5 cursor-pointer ${
                    isSelected
                      ? 'bg-purple-600 text-white shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                  }`}
                >
                  {getAgentIcon(a.key, 'w-3 h-3')}
                  <span>{meta.displayName.replace(' Bot', '')}</span>
                </button>
              );
            })}
          </div>

          {/* Action Controls & Zero-Trust Verification Badge */}
          <div className="flex items-center space-x-2">
            <button
              onClick={handleStartNewConversation}
              className="py-1.5 px-3 rounded-xl bg-purple-600/20 hover:bg-purple-600/30 border border-purple-500/40 text-purple-200 text-xs font-medium flex items-center space-x-1.5 transition-all shadow-sm cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">New Chat</span>
            </button>

            <div className="hidden sm:flex items-center space-x-1.5 px-2.5 py-1.5 rounded-full bg-slate-900 border border-slate-800 text-xs">
              <Shield className="w-3.5 h-3.5 text-emerald-400" />
              <span className="font-mono text-[10px] text-emerald-400 font-semibold tracking-wide">
                ZERO-TRUST
              </span>
            </div>
          </div>
        </div>

        {/* Messages Container or Welcome Screen */}
        <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-6">
          {messages.length === 0 ? (
            /* Welcome Screen tailored to the active Chatbot */
            <div className="max-w-2xl mx-auto py-12 flex flex-col items-center text-center space-y-5">
              <div className="p-4 rounded-3xl bg-slate-900 border border-slate-800 shadow-2xl relative">
                {currentAgent && getAgentIcon(currentAgent.key, 'w-10 h-10')}
                <span className="absolute -bottom-1 -right-1 w-4 h-4 rounded-full bg-emerald-500 border-2 border-slate-950 flex items-center justify-center">
                  <span className="w-2 h-2 rounded-full bg-emerald-300 animate-ping" />
                </span>
              </div>

              <div>
                <h1 className="text-3xl sm:text-4xl font-bold text-white tracking-tight">
                  Chat with {activeMeta.displayName}
                </h1>
                <p className="text-sm text-slate-400 mt-2 max-w-lg mx-auto leading-relaxed">
                  {activeMeta.tagline}
                </p>
              </div>

              {/* Status Pill */}
              <div className="flex items-center space-x-2 px-3.5 py-1.5 rounded-full bg-slate-900 border border-slate-800 text-xs text-slate-300">
                <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                <span>AI Assistant Ready</span>
              </div>

              {/* Suggested Prompts for this Bot */}
              <div className="w-full space-y-2 pt-4">
                <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider text-left">
                  Suggested Prompts for {activeMeta.displayName}
                </div>
                <div className="grid grid-cols-1 gap-2">
                  {activeMeta.prompts.map((prompt, idx) => (
                    <button
                      key={idx}
                      onClick={() => handleSendMessage(prompt)}
                      className="p-3.5 text-left rounded-xl bg-slate-900/60 hover:bg-slate-900 border border-slate-800/80 hover:border-purple-500/40 text-xs text-slate-300 hover:text-white transition-all flex items-center justify-between group cursor-pointer"
                    >
                      <span className="mr-2">"{prompt}"</span>
                      <Send className="w-3.5 h-3.5 text-slate-500 group-hover:text-purple-400 opacity-60 group-hover:opacity-100 transition-all shrink-0" />
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
                      {isUser ? (
                        <UserIcon className="w-4 h-4" />
                      ) : isBlocked ? (
                        <ShieldAlert className="w-4 h-4" />
                      ) : currentAgent ? (
                        getAgentIcon(currentAgent.key, 'w-4 h-4')
                      ) : (
                        <Bot className="w-4 h-4" />
                      )}
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
                          <span className="font-mono text-[10px]">{m.model || activeMeta.displayName}</span>
                          <button
                            onClick={() => handleCopy(m.content, m.id)}
                            className="flex items-center space-x-1 text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
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

        {/* Message Composer (Gemini Pill Style) */}
        <div className="p-4 border-t border-slate-800/80 bg-slate-950/80 backdrop-blur-md shrink-0">
          <div className="max-w-3xl mx-auto space-y-2">
            {/* Attached Files & Live Status Chips */}
            {(attachedFiles.length > 0 || isUploadingFile || isListening || fileUploadError) && (
              <div className="flex flex-wrap items-center gap-2 px-3 py-1">
                {isListening && (
                  <div className="flex items-center space-x-2 px-3 py-1 rounded-full bg-red-950/80 border border-red-500/50 text-red-300 text-xs animate-pulse shadow-sm">
                    <span className="w-2 h-2 rounded-full bg-red-500 animate-ping" />
                    <span className="font-medium">Listening to your voice... (Click mic to finish)</span>
                  </div>
                )}

                {isUploadingFile && (
                  <div className="flex items-center space-x-2 px-3 py-1 rounded-full bg-purple-950/80 border border-purple-500/50 text-purple-300 text-xs shadow-sm">
                    <Loader2 className="w-3.5 h-3.5 animate-spin text-purple-400" />
                    <span>Uploading & scanning document...</span>
                  </div>
                )}

                {fileUploadError && (
                  <div className="flex items-center space-x-1.5 px-3 py-1 rounded-full bg-red-950/80 border border-red-500/50 text-red-300 text-xs shadow-sm">
                    <span>⚠️ {fileUploadError}</span>
                  </div>
                )}

                {attachedFiles.map((file) => (
                  <div
                    key={file.id}
                    className="flex items-center space-x-2 px-3 py-1 rounded-full bg-slate-900 border border-slate-700/80 text-slate-200 text-xs shadow-sm hover:border-purple-500/50 transition-colors"
                  >
                    <FileText className="w-3.5 h-3.5 text-purple-400 shrink-0" />
                    <span className="font-medium truncate max-w-[160px]">{file.original_name}</span>
                    <span className="text-[10px] text-slate-400 font-mono">({Math.round(file.file_size / 1024)} KB)</span>
                    <button
                      type="button"
                      onClick={() => handleRemoveFile(file.id)}
                      className="text-slate-400 hover:text-red-400 p-0.5 rounded-full hover:bg-slate-800 transition-colors cursor-pointer"
                      title="Remove attached file"
                    >
                      <X className="w-3 h-3" />
                    </button>
                  </div>
                ))}
              </div>
            )}

            {/* Gemini-Style Pill Input Capsule */}
            <div className="relative flex items-center bg-slate-900 border border-slate-700/80 hover:border-slate-600 focus-within:border-purple-500/70 focus-within:ring-2 focus-within:ring-purple-500/20 rounded-full pl-3 pr-2 py-1.5 shadow-2xl transition-all">
              {/* Left: + File Attachment Button */}
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                title="Attach document (.txt, .pdf, .csv, .md, .json)"
                className="p-2 rounded-full text-slate-400 hover:text-white hover:bg-slate-800 transition-colors shrink-0 cursor-pointer"
              >
                <Plus className="w-5 h-5" />
              </button>
              <input
                ref={fileInputRef}
                type="file"
                accept=".txt,.pdf,.csv,.md,.json"
                className="hidden"
                onChange={handleFileSelect}
              />

              {/* Center: Input Textarea */}
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
                placeholder={`Chat with ${activeMeta.displayName}...`}
                className="flex-1 bg-transparent px-3 py-1.5 text-sm text-slate-100 placeholder-slate-400 focus:outline-none resize-none max-h-32 leading-relaxed"
              />

              {/* Right: Agent Selection Dropdown Pill */}
              <div className="relative flex items-center mr-1.5 shrink-0">
                <select
                  value={currentAgent?.key || ''}
                  onChange={(e) => {
                    const k = e.target.value;
                    const matched = agents.find((a) => a.key === k);
                    if (matched) handleSelectAgent(matched);
                  }}
                  className="appearance-none bg-slate-800/90 hover:bg-slate-800 text-slate-200 text-xs font-medium rounded-full pl-3 pr-7 py-1.5 border border-slate-700/60 cursor-pointer focus:outline-none focus:border-purple-500 transition-colors shadow-sm"
                >
                  {agents.map((a) => {
                    const meta = getAgentMeta(a.key);
                    return (
                      <option key={a.key} value={a.key} className="bg-slate-900 text-slate-200">
                        {meta.displayName}
                      </option>
                    );
                  })}
                </select>
                <ChevronDown className="w-3.5 h-3.5 text-slate-400 absolute right-2.5 pointer-events-none" />
              </div>

              {/* Far Right: Mic / Send / Stop Button */}
              {isStreaming ? (
                <button
                  onClick={handleStopStreaming}
                  title="Stop generation"
                  className="p-2 rounded-full bg-red-600/80 hover:bg-red-600 text-white transition-colors shrink-0 cursor-pointer"
                >
                  <Square className="w-4 h-4 fill-current" />
                </button>
              ) : (inputValue.trim() || attachedFiles.length > 0) ? (
                <button
                  onClick={() => handleSendMessage()}
                  title="Send message"
                  className="p-2 rounded-full bg-purple-600 hover:bg-purple-500 text-white shadow-md shadow-purple-950/50 transition-all shrink-0 cursor-pointer"
                >
                  <Send className="w-4 h-4" />
                </button>
              ) : (
                <button
                  type="button"
                  onClick={toggleListening}
                  title={isListening ? 'Listening... Click to stop' : 'Voice input (Speech to text)'}
                  className={`p-2 rounded-full transition-all shrink-0 cursor-pointer ${
                    isListening
                      ? 'bg-red-500/20 text-red-400 ring-2 ring-red-500/50 animate-pulse'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                  }`}
                >
                  <Mic className="w-4 h-4" />
                </button>
              )}
            </div>

            <div className="flex items-center justify-between text-[11px] text-slate-500 px-4 font-mono">
              <span>Enter to send · Shift+Enter for newline</span>
              <span className="text-slate-400">
                Review generated responses for accuracy
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

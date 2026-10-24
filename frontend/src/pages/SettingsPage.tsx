import React, { useEffect, useState } from 'react';
import {
  Settings,
  Shield,
  Database,
  Cpu,
  Upload,
  Trash2,
  FileText,
  CheckCircle2,
  AlertTriangle,
  User as UserIcon,
  Key,
  RefreshCw
} from 'lucide-react';
import { api } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { UploadedFileItem } from '../types';

export const SettingsPage: React.FC = () => {
  const { user } = useAuth();
  const [health, setHealth] = useState<any>(null);
  const [files, setFiles] = useState<UploadedFileItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [uploading, setUploading] = useState<boolean>(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [geminiKeyInput, setGeminiKeyInput] = useState<string>('');
  const [savingKey, setSavingKey] = useState<boolean>(false);
  const [keySaveFeedback, setKeySaveFeedback] = useState<string | null>(null);

  const handleSaveGeminiKey = async () => {
    if (!geminiKeyInput.trim()) return;
    setSavingKey(true);
    setKeySaveFeedback(null);
    try {
      const res = await api.updateGeminiKey(geminiKeyInput.trim());
      setKeySaveFeedback(res.message || 'Key saved successfully');
      setGeminiKeyInput('');
      loadData();
    } catch (err: any) {
      setKeySaveFeedback(err.message || 'Failed to save key');
    } finally {
      setSavingKey(false);
    }
  };

  const loadData = async () => {
    setLoading(true);
    try {
      const [h, f] = await Promise.all([
        api.getHealth(),
        api.getFiles(),
      ]);
      setHealth(h);
      setFiles(f);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setUploading(true);
    setUploadError(null);
    try {
      const uploaded = await api.uploadFile(file);
      setFiles([uploaded, ...files]);
    } catch (err: any) {
      setUploadError(err.message || 'File upload failed');
    } finally {
      setUploading(false);
      e.target.value = '';
    }
  };

  const handleDeleteFile = async (id: string) => {
    if (!confirm('Delete this file?')) return;
    try {
      await api.deleteFile(id);
      setFiles(files.filter((f) => f.id !== id));
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Header */}
      <div className="border-b border-slate-800/80 pb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center space-x-2">
            <span>Platform Settings & Health</span>
            <span className="text-xs font-mono font-medium px-2 py-0.5 rounded-full bg-purple-950 text-purple-300 border border-purple-800/50">
              CONFIG & DIAGNOSTICS
            </span>
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            System runtime status, Google Gemini configuration, and secure document storage.
          </p>
        </div>
        <button
          onClick={loadData}
          className="flex items-center space-x-2 px-3 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-700/80 rounded-xl text-xs font-medium text-slate-200 transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5 text-purple-400" />
          <span>Refresh Health</span>
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* User Profile Card */}
        <div className="p-6 rounded-2xl border border-slate-800 bg-slate-950/60 backdrop-blur-md space-y-4">
          <div className="flex items-center space-x-3 text-white font-bold text-base">
            <div className="p-2.5 rounded-xl bg-purple-950 border border-purple-700/50 text-purple-300">
              <UserIcon className="w-5 h-5" />
            </div>
            <div>
              <h3>Operator Profile</h3>
              <span className="text-xs text-slate-400 font-normal">Active session details</span>
            </div>
          </div>

          <div className="space-y-2 text-xs divide-y divide-slate-800/60 pt-2">
            <div className="py-2 flex justify-between">
              <span className="text-slate-400">Full Name</span>
              <span className="font-semibold text-slate-200">{user?.full_name}</span>
            </div>
            <div className="py-2 flex justify-between">
              <span className="text-slate-400">Email Address</span>
              <span className="font-semibold text-slate-200">{user?.email}</span>
            </div>
            <div className="py-2 flex justify-between">
              <span className="text-slate-400">Security Role</span>
              <span className="font-mono text-purple-400 uppercase font-semibold">{user?.role}</span>
            </div>
            <div className="py-2 flex justify-between">
              <span className="text-slate-400">User ID</span>
              <span className="font-mono text-slate-500">{user?.id}</span>
            </div>
          </div>
        </div>

        {/* Gemini Integration Status Card */}
        <div className="p-6 rounded-2xl border border-slate-800 bg-slate-950/60 backdrop-blur-md space-y-4">
          <div className="flex items-center space-x-3 text-white font-bold text-base">
            <div className="p-2.5 rounded-xl bg-indigo-950 border border-indigo-700/50 text-indigo-300">
              <Cpu className="w-5 h-5" />
            </div>
            <div>
              <h3>Google Gemini Integration</h3>
              <span className="text-xs text-slate-400 font-normal">Official Gen AI SDK connectivity</span>
            </div>
          </div>

          <div className="space-y-2 text-xs divide-y divide-slate-800/60 pt-2">
            <div className="py-2 flex justify-between items-center">
              <span className="text-slate-400">Configured Model</span>
              <span className="font-mono font-semibold text-purple-300">
                {health?.gemini?.model || 'gemini-1.5-flash'}
              </span>
            </div>
            <div className="py-2 flex justify-between items-center">
              <span className="text-slate-400">API Key Status</span>
              <span className={`inline-flex items-center space-x-1 font-semibold ${
                health?.gemini?.configured ? 'text-emerald-400' : 'text-amber-400'
              }`}>
                {health?.gemini?.configured ? (
                  <>
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>Configured in Backend</span>
                  </>
                ) : (
                  <>
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>Not Set in .env</span>
                  </>
                )}
              </span>
            </div>
            <div className="py-2 flex justify-between items-center">
              <span className="text-slate-400">Readiness</span>
              <span className="text-slate-300">{health?.gemini?.message}</span>
            </div>
          </div>

          {/* Interactive API Key Input */}
          <div className="pt-2 border-t border-slate-800 space-y-2">
            <label className="text-xs font-semibold text-slate-300 flex items-center space-x-1.5">
              <Key className="w-3.5 h-3.5 text-purple-400" />
              <span>Configure Gemini API Key</span>
            </label>
            <div className="flex gap-2">
              <input
                type="password"
                placeholder="Paste your Google AI Studio API key here (AIza...)"
                value={geminiKeyInput}
                onChange={(e) => setGeminiKeyInput(e.target.value)}
                className="flex-1 bg-slate-900 border border-slate-700 rounded-xl px-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-purple-500 font-mono"
              />
              <button
                disabled={savingKey || !geminiKeyInput.trim()}
                onClick={handleSaveGeminiKey}
                className="px-3 py-1.5 bg-purple-600 hover:bg-purple-500 disabled:opacity-40 rounded-xl text-xs font-semibold text-white transition-all shadow-md shrink-0"
              >
                {savingKey ? 'Saving...' : 'Save Key'}
              </button>
            </div>
            {keySaveFeedback && (
              <p className={`text-xs ${keySaveFeedback.includes('success') ? 'text-emerald-400' : 'text-red-400'}`}>
                {keySaveFeedback}
              </p>
            )}
            <p className="text-[11px] text-slate-500">
              Obtain your free Gemini API key from <a href="https://aistudio.google.com/" target="_blank" rel="noreferrer" className="text-purple-400 underline">Google AI Studio</a>. The key is securely stored in your backend configuration.
            </p>
          </div>
        </div>
      </div>

      {/* Security Gateway Diagnostic Card */}
      <div className="p-6 rounded-2xl border border-slate-800 bg-slate-950/60 backdrop-blur-md space-y-4">
        <div className="flex items-center space-x-3 text-white font-bold text-base">
          <div className="p-2.5 rounded-xl bg-emerald-950 border border-emerald-700/50 text-emerald-300">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <h3>Security Gateway Engine</h3>
            <span className="text-xs text-slate-400 font-normal">Active deterministic threat detectors</span>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 pt-2">
          {health?.security_gateway?.active_guardrails?.map((guardrail: string) => (
            <div
              key={guardrail}
              className="p-3 rounded-xl bg-slate-900 border border-slate-800 flex items-center space-x-2.5 text-xs"
            >
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span className="font-mono text-slate-300">{guardrail}</span>
            </div>
          ))}
        </div>
      </div>

      {/* User Document Storage (For File & Data Analysis Agents) */}
      <div className="p-6 rounded-2xl border border-slate-800 bg-slate-950/60 backdrop-blur-md space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h3 className="font-bold text-white text-base flex items-center space-x-2">
              <FileText className="w-5 h-5 text-purple-400" />
              <span>Workspace Document Management</span>
            </h3>
            <p className="text-xs text-slate-400">
              Upload compliance docs, datasets, and text files for File Agent and Data Analysis Agent.
            </p>
          </div>

          <label className="cursor-pointer inline-flex items-center space-x-2 px-4 py-2 bg-purple-600 hover:bg-purple-500 rounded-xl text-xs font-semibold text-white shadow-md shadow-purple-950/40 transition-all self-start">
            <Upload className="w-4 h-4" />
            <span>{uploading ? 'Processing File...' : 'Upload Document'}</span>
            <input
              type="file"
              disabled={uploading}
              onChange={handleFileUpload}
              accept=".txt,.pdf,.csv,.md,.json"
              className="hidden"
            />
          </label>
        </div>

        {uploadError && (
          <div className="p-3 rounded-xl bg-red-950/50 border border-red-500/50 text-red-300 text-xs">
            {uploadError}
          </div>
        )}

        {files.length === 0 ? (
          <div className="p-8 text-center text-slate-500 text-xs border border-dashed border-slate-800 rounded-xl">
            No uploaded files in your tenant workspace. Click "Upload Document" to add text, PDF, or CSV files.
          </div>
        ) : (
          <div className="divide-y divide-slate-800/80">
            {files.map((file) => (
              <div key={file.id} className="py-3 flex items-center justify-between text-xs">
                <div className="space-y-0.5">
                  <div className="font-semibold text-slate-200 flex items-center space-x-2">
                    <span>{file.original_name}</span>
                    <span className="font-mono text-[10px] uppercase px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-purple-300">
                      {file.file_type}
                    </span>
                  </div>
                  <div className="text-slate-500 font-mono text-[11px]">
                    Size: {(file.file_size / 1024).toFixed(1)} KB · Uploaded: {new Date(file.created_at).toLocaleDateString()}
                  </div>
                </div>
                <button
                  onClick={() => handleDeleteFile(file.id)}
                  className="p-1.5 text-slate-400 hover:text-red-400 rounded-lg hover:bg-slate-900"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

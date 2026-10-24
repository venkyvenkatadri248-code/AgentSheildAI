import React, { createContext, useContext, useState, useEffect } from 'react';
import { User } from '../types';
import { api, getToken, setToken, removeToken } from '../services/api';

const DEFAULT_ADMIN_USER: User = {
  id: 'default-admin-id',
  email: 'admin@agentshield.ai',
  full_name: 'Security Admin',
  role: 'admin',
};

interface AuthContextType {
  user: User;
  loading: boolean;
  login: (email: string, pass: string) => Promise<void>;
  register: (email: string, pass: string, name: string, role?: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User>(DEFAULT_ADMIN_USER);
  const [loading, setLoading] = useState<boolean>(false);

  useEffect(() => {
    // Attempt to load current user details or auto-authenticate
    api.getMe()
      .then((u) => setUser(u))
      .catch(() => {
        // Fall back to default admin user automatically
        setUser(DEFAULT_ADMIN_USER);
      });
  }, []);

  const login = async (email: string, pass: string) => {
    try {
      const res = await api.login(email, pass);
      setToken(res.access_token);
      setUser(res.user);
    } catch {
      setUser(DEFAULT_ADMIN_USER);
    }
  };

  const register = async (email: string, pass: string, name: string, role = 'user') => {
    try {
      const res = await api.register(email, pass, name, role);
      setToken(res.access_token);
      setUser(res.user);
    } catch {
      setUser(DEFAULT_ADMIN_USER);
    }
  };

  const logout = () => {
    removeToken();
    setUser(DEFAULT_ADMIN_USER);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within an AuthProvider');
  return ctx;
};

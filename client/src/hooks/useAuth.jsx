import { createContext, useContext, useState, useEffect } from 'react';
import { api, refreshSession, setAccessToken } from '../lib/api.js';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser]       = useState(null);
  const [loading, setLoading] = useState(true);

  // On load, the refresh cookie (if any) is exchanged for an access token.
  useEffect(() => {
    refreshSession()
      .then(data => setUser(data?.user ?? null))
      .finally(() => setLoading(false));
  }, []);

  // Re-fetch the live user record; picks up a fresh token if the role changed.
  const refreshUser = async () => {
    try {
      const data = await api.me();
      if (data?.token) setAccessToken(data.token);
      if (data?.user) setUser(data.user);
      return data?.user ?? null;
    } catch {
      return null;
    }
  };

  const login = async (email, password) => {
    const data = await api.login({ email, password });
    setAccessToken(data.token);
    setUser(data.user);
    return data.user;
  };

  const signup = async (email, password) => {
    const data = await api.signup({ email, password });
    setAccessToken(data.token);
    setUser(data.user);
    return data.user;
  };

  const logout = async () => {
    try { await api.logout(); } catch { /* already signed out */ }
    setAccessToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, signup, logout, refreshUser }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}

import { createContext, useContext, useState, useEffect } from 'react';
import { api } from '../lib/api.js';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser]       = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (!token) { setLoading(false); return; }

    api.me()
      .then(data => {
        if (data?.token) localStorage.setItem('token', data.token); // role changed → fresh token
        setUser(data.user);
      })
      .catch(() => localStorage.removeItem('token'))
      .finally(() => setLoading(false));
  }, []);

  // Re-fetch the live user record; picks up a refreshed token if the role changed.
  const refreshUser = async () => {
    try {
      const data = await api.me();
      if (data?.token) localStorage.setItem('token', data.token);
      if (data?.user) setUser(data.user);
      return data?.user ?? null;
    } catch {
      return null;
    }
  };

  const login = async (email, password) => {
    const data = await api.login({ email, password });
    localStorage.setItem('token', data.token);
    setUser(data.user);
    return data.user;
  };

  const signup = async (email, password) => {
    const data = await api.signup({ email, password });
    localStorage.setItem('token', data.token);
    setUser(data.user);
    return data.user;
  };

  const logout = () => {
    localStorage.removeItem('token');
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

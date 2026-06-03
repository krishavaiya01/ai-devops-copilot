import axios from 'axios';

// The backend dev server runs on port 8000
const API_BASE_URL = 'http://localhost:8000/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Interceptor to attach JWT token to all requests
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Auth Service Endpoints
export const authService = {
  login: async (username: string, password: string) => {
    const params = new URLSearchParams();
    params.append('username', username);
    params.append('password', password);
    const response = await api.post('/auth/login', params, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });
    return response.data;
  },
  signup: async (userData: any) => {
    const response = await api.post('/auth/signup', userData);
    return response.data;
  },
  getMe: async () => {
    const response = await api.get('/auth/me');
    return response.data;
  },
};

// Logs Service Endpoints
export const logsService = {
  analyze: async (content: string, incidentId?: number) => {
    const response = await api.post('/logs/analyze', { content, incident_id: incidentId });
    return response.data;
  },
  getLogs: async (incidentId?: number) => {
    const response = await api.get('/logs', {
      params: incidentId ? { incident_id: incidentId } : {},
    });
    return response.data;
  },
};

// Incidents Service Endpoints
export const incidentsService = {
  getIncidents: async () => {
    const response = await api.get('/incidents');
    return response.data;
  },
  getIncident: async (id: number) => {
    const response = await api.get(`/incidents/${id}`);
    return response.data;
  },
  createIncident: async (incidentData: any) => {
    const response = await api.post('/incidents', incidentData);
    return response.data;
  },
  updateIncident: async (id: number, incidentData: any) => {
    const response = await api.put(`/incidents/${id}`, incidentData);
    return response.data;
  },
  deleteIncident: async (id: number) => {
    const response = await api.delete(`/incidents/${id}`);
    return response.data;
  },
};

// Alerts Service Endpoints
export const alertsService = {
  getAlerts: async () => {
    const response = await api.get('/alerts');
    return response.data;
  },
  createAlert: async (alertData: any) => {
    const response = await api.post('/alerts', alertData);
    return response.data;
  },
  updateAlert: async (id: number, status: string) => {
    const response = await api.put(`/alerts/${id}`, { status });
    return response.data;
  },
};

// Cloud cost optimization Service Endpoints
export const costService = {
  getRecommendations: async () => {
    const response = await api.get('/recommendations/cost');
    return response.data;
  },
  updateRecommendation: async (id: number, status: string) => {
    const response = await api.put(`/recommendations/cost/${id}`, { status });
    return response.data;
  },
  getResources: async () => {
    const response = await api.get('/recommendations/resources');
    return response.data;
  },
};

// AI Chat Service Endpoints
export const chatService = {
  sendMessage: async (sessionId: string, content: string) => {
    const response = await api.post('/chat/message', { session_id: sessionId, content });
    return response.data;
  },
  getSessionMessages: async (sessionId: string) => {
    const response = await api.get(`/chat/sessions/${sessionId}`);
    return response.data;
  },
};

// Metrics Service Endpoints
export const metricsService = {
  getDashboardMetrics: async () => {
    // Falls back to direct endpoints on the server (which resolves to local mock metrics generator)
    const response = await api.get('/metrics/dashboard');
    return response.data;
  },
};

export default api;
export { API_BASE_URL };

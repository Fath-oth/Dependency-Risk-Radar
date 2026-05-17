// stores/useStore.js
import { create } from 'zustand';
import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const api = axios.create({ baseURL: API_BASE });

export const useStore = create((set, get) => ({
  // ── Reports list ──
  reports: [],
  reportsLoading: false,
  fetchReports: async () => {
    set({ reportsLoading: true });
    try {
      const { data } = await api.get('/api/v1/reports');
      set({ reports: data });
    } finally {
      set({ reportsLoading: false });
    }
  },

  // ── Active report ──
  activeReport: null,
  activeReportLoading: false,
  fetchReport: async (reportId) => {
    set({ activeReportLoading: true, activeReport: null });
    try {
      const { data } = await api.get(`/api/v1/reports/${reportId}`);
      set({ activeReport: data });
    } finally {
      set({ activeReportLoading: false });
    }
  },

  // ── Analysis job ──
  activeJob: null,
  jobProgress: 0,
  jobMessage: '',
  startGradleAnalysis: async (projectPath) => {
    const { data } = await api.post('/api/v1/analyze/gradle', { project_path: projectPath });
    set({ activeJob: data.job_id, jobProgress: 0, jobMessage: 'Queued' });
    get()._pollJob(data.job_id);
    return data.job_id;
  },
  startApkAnalysis: async (file) => {
    const formData = new FormData();
    formData.append('file', file);
    const { data } = await api.post('/api/v1/analyze/apk', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    set({ activeJob: data.job_id, jobProgress: 0, jobMessage: 'Queued' });
    get()._pollJob(data.job_id);
    return data.job_id;
  },
  _pollJob: async (jobId) => {
    const poll = async () => {
      try {
        const { data } = await api.get(`/api/v1/jobs/${jobId}`);
        set({ jobProgress: data.progress || 0, jobMessage: data.message || '' });
        if (data.status === 'completed') {
          set({ activeJob: null });
          if (data.report_id) {
            await get().fetchReport(data.report_id);
            await get().fetchReports();
          }
        } else if (data.status === 'failed') {
          set({ activeJob: null, jobMessage: `Failed: ${data.error}` });
        } else {
          setTimeout(poll, 800);
        }
      } catch {
        setTimeout(poll, 2000);
      }
    };
    setTimeout(poll, 800);
  },

  // ── Graph data ──
  graphData: null,
  fetchGraph: async (reportId) => {
    const { data } = await api.get(`/api/v1/reports/${reportId}/graph`);
    set({ graphData: data });
  },

  // ── UI state ──
  selectedComponent: null,
  setSelectedComponent: (comp) => set({ selectedComponent: comp }),
  sidebarOpen: true,
  toggleSidebar: () => set((s) => ({ sidebarOpen: !s.sidebarOpen })),
}));

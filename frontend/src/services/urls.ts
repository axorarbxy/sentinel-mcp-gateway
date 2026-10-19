/** Shared same-origin URLs for local development and Vercel deployments. */
const isLocalDevelopment =
  typeof window !== 'undefined' &&
  (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1');

export const API_BASE_URL =
  process.env.REACT_APP_API_URL ?? (isLocalDevelopment ? 'http://localhost:8001' : '');

export const WEBSOCKET_BASE_URL = API_BASE_URL
  ? API_BASE_URL.replace(/^http/, 'ws')
  : `${typeof window !== 'undefined' && window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${typeof window !== 'undefined' ? window.location.host : 'localhost'}`;

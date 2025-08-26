// Mock auth.js to avoid import.meta.url issues in tests
import { config } from './config.js';
import dotenv from 'dotenv';

dotenv.config();

export const getAccessToken = jest.fn().mockResolvedValue('mock-access-token');
export const getRefreshToken = jest.fn().mockResolvedValue('mock-refresh-token');
export const refreshAccessToken = jest.fn().mockResolvedValue('mock-refreshed-token');
export const exchangeCodeForTokens = jest.fn().mockResolvedValue({
    accessToken: 'mock-access-token',
    refreshToken: 'mock-refresh-token',
    expiresIn: 3600
});
export const generateAuthUrl = jest.fn().mockReturnValue('https://mock-auth-url.com');
export const saveTokens = jest.fn().mockResolvedValue(true);
export const loadTokens = jest.fn().mockResolvedValue({
    accessToken: 'mock-access-token',
    refreshToken: 'mock-refresh-token',
    expiresIn: 3600
});

import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';
import { readDeploymentCsp } from './scripts/deploymentCsp';

export default defineConfig(() => {
  const managementTarget =
    process.env.SENTINELFLOW_MANAGEMENT_API_URL ?? 'http://127.0.0.1:8083';
  const deploymentCsp =
    process.env.SENTINELFLOW_PREVIEW_DEPLOYMENT_CSP === '1'
      ? readDeploymentCsp()
      : null;
  const managementProxy = {
    target: managementTarget,
    changeOrigin: false,
    secure: true,
    ws: false,
  } as const;

  return {
    plugins: [react()],
    server: {
      host: '127.0.0.1',
      port: 5173,
      strictPort: true,
      proxy: { '/api': managementProxy },
    },
    preview: {
      host: '127.0.0.1',
      port: 4173,
      strictPort: true,
      proxy: { '/api': managementProxy },
      ...(deploymentCsp
        ? { headers: { 'Content-Security-Policy': deploymentCsp } }
        : {}),
    },
    build: {
      manifest: true,
      rolldownOptions: {
        output: {
          codeSplitting: {
            groups: [
              {
                name: 'react-runtime',
                test: /node_modules[\\/](?:react|react-dom|react-router|react-router-dom|scheduler)[\\/]/,
                priority: 30,
              },
            ],
          },
        },
      },
    },
    test: {
      environment: 'jsdom',
      setupFiles: './src/test/setup.ts',
      testTimeout: 10_000,
      css: true,
      exclude: ['tests/**', 'node_modules/**', 'dist/**'],
    },
  };
});

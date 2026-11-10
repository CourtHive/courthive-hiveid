// PM2 process definition for courthive-hiveid (the HiveID IdP).
// Mirrors courthive-declarations / courthive-ams. Env is supplied by the
// shared deploy `.env` (blue-green layout: current -> releases/<id>, .env
// symlinked from ../../shared/.env).

module.exports = {
  apps: [
    {
      name: 'courthive-hiveid',
      script: 'build/main.js',
      instances: 1,
      exec_mode: 'fork',
      env: {
        NODE_ENV: 'production',
      },
    },
  ],
};

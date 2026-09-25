/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Emit a self-contained Node.js server under .next/standalone so the
  // production Docker image needs no node_modules at runtime.
  output: "standalone",
  experimental: {
    typedRoutes: true,
  },
};

module.exports = nextConfig;

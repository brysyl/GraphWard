import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "GraphWard AI — Autonomous Code Remediation",
  description:
    "Enterprise-grade autonomous code remediation platform. AST analysis, CVE detection, and zero-breakage patch verification.",
  icons: { icon: "/favicon.ico" },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="bg-[#080d1a] text-slate-100 antialiased">{children}</body>
    </html>
  );
}

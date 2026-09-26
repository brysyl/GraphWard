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
      <body className="bg-[#080d1a] text-slate-100 antialiased">
        {children}
      </body>
    </html>
  );
}

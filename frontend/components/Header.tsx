"use client";

import { useEffect, useState } from "react";

export default function Header() {
  const [online, setOnline] = useState<boolean | null>(null);

  useEffect(() => {
    fetch("/api/health")
      .then((res) => setOnline(res.ok))
      .catch(() => setOnline(false));
  }, []);

  return (
    <header className="flex items-center justify-between px-6 py-3 border-b border-slate-800 bg-[#080d1a]">
      <span className="font-semibold tracking-wide text-slate-100">GraphWard AI</span>
      <div className="flex items-center gap-2 text-sm">
        <span
          className={`h-2.5 w-2.5 rounded-full ${
            online === true
              ? "bg-green-500"
              : online === false
              ? "bg-red-500"
              : "bg-slate-500"
          }`}
        />
        <span className="text-slate-400">
          {online === true ? "online" : online === false ? "offline" : "…"}
        </span>
      </div>
    </header>
  );
}

"use client";

import { useEffect, useRef, useState } from "react";
import "xterm/css/xterm.css";

interface ScanTerminalProps {
  logs: string[];
  height?: number;
}

export function ScanTerminal({ logs, height = 400 }: ScanTerminalProps) {
  const termRef = useRef<HTMLDivElement>(null);
  const xtermRef = useRef<unknown>(null);
  const fitAddonRef = useRef<unknown>(null);
  const writtenCount = useRef<number>(0);
  const [isReady, setIsReady] = useState(false);

  useEffect(() => {
    if (typeof window === "undefined") return;

    let mounted = true;

    async function initTerminal() {
      const { Terminal } = await import("xterm");
      const { FitAddon } = await import("xterm-addon-fit");

      if (!mounted || !termRef.current) return;

      const term = new Terminal({
        theme: {
          background: "#0f1117",
          foreground: "#c9d1d9",
          cursor: "#58a6ff",
          selectionBackground: "#2d4a7a",
        },
        fontFamily: "'JetBrains Mono', 'Fira Code', Consolas, monospace",
        fontSize: 13,
        lineHeight: 1.4,
        cursorBlink: false,
        scrollback: 10000,
        disableStdin: true,
        convertEol: true,
      });

      const fitAddon = new FitAddon();
      term.loadAddon(fitAddon);
      term.open(termRef.current);
      fitAddon.fit();

      xtermRef.current = term;
      fitAddonRef.current = fitAddon;
      writtenCount.current = 0;
      setIsReady(true);
    }

    initTerminal();

    return () => {
      mounted = false;
      if (xtermRef.current) {
        (xtermRef.current as { dispose: () => void }).dispose();
        xtermRef.current = null;
      }
      setIsReady(false);
    };
  }, []);

  // Write logs to terminal - handles both initial batch and live updates
  useEffect(() => {
    if (!isReady) return;
    const term = xtermRef.current as
      | { writeln: (s: string) => void; clear: () => void; scrollToBottom: () => void }
      | null;
    if (!term) return;

    // If logs shrunk (new scan/reset), clear and rewrite
    if (logs.length < writtenCount.current) {
      term.clear();
      writtenCount.current = 0;
    }

    // Write any new logs since last render
    for (let i = writtenCount.current; i < logs.length; i++) {
      const line = logs[i];
      if (line !== undefined && line !== null) {
        term.writeln(String(line).replace(/\r?\n$/, ""));
      }
    }
    writtenCount.current = logs.length;

    if (logs.length > 0) term.scrollToBottom();
  }, [logs, isReady]);

  // Resize observer
  useEffect(() => {
    if (!termRef.current) return;
    const ro = new ResizeObserver(() => {
      const fit = fitAddonRef.current as { fit: () => void } | null;
      fit?.fit();
    });
    ro.observe(termRef.current);
    return () => ro.disconnect();
  }, []);

  return (
    <div
      className="rounded-lg border border-border overflow-hidden bg-[#0f1117]"
      style={{ height }}
    >
      <div className="flex items-center gap-2 px-4 py-2 border-b border-border bg-secondary">
        <div className="w-3 h-3 rounded-full bg-red-500" />
        <div className="w-3 h-3 rounded-full bg-yellow-500" />
        <div className="w-3 h-3 rounded-full bg-green-500" />
        <span className="text-xs text-muted-foreground ml-2 font-mono">scan output</span>
      </div>
      <div ref={termRef} style={{ height: height - 41 }} />
    </div>
  );
}

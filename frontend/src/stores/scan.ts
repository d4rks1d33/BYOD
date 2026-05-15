import { create } from "zustand";
import type { Scan, WSScanEvent } from "@/types";

interface ScanState {
  activeScan: Scan | null;
  scanLogs: string[];
  progress: number;
  phase: string;
  setActiveScan: (scan: Scan | null) => void;
  appendLog: (line: string) => void;
  clearLogs: () => void;
  handleWsEvent: (event: WSScanEvent) => void;
}

export const useScanStore = create<ScanState>()((set) => ({
  activeScan: null,
  scanLogs: [],
  progress: 0,
  phase: "",

  setActiveScan: (scan) => set({ activeScan: scan }),

  appendLog: (line) =>
    set((state) => ({ scanLogs: [...state.scanLogs.slice(-2000), line] })),

  clearLogs: () => set({ scanLogs: [], progress: 0, phase: "" }),

  handleWsEvent: (event) => {
    set((state) => {
      const updates: Partial<ScanState> = {};

      if (event.type === "scan.log" && event.message) {
        updates.scanLogs = [...state.scanLogs.slice(-2000), event.message];
      }
      if (event.type === "scan.progress" && event.progress !== undefined) {
        updates.progress = event.progress;
      }
      if (event.type === "scan.phase" && event.phase) {
        updates.phase = event.phase;
      }
      if (event.type === "scan.complete" || event.type === "scan.failed") {
        updates.progress = 100;
        updates.phase = event.type === "scan.complete" ? "complete" : "failed";
      }

      return updates;
    });
  },
}));

"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { scans as api } from "@/lib/api";
import type { Scan } from "@/types";

export function useScanList(projectId: string) {
  return useQuery({
    queryKey: ["scans", projectId],
    queryFn: () => api.list(projectId),
    enabled: !!projectId,
    refetchInterval: 5000,
  });
}

export function useScan(scanId: string) {
  return useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => api.get(scanId),
    enabled: !!scanId,
    refetchInterval: (query) => {
      const scan = query.state.data as Scan | undefined;
      return scan?.status === "running" ? 3000 : false;
    },
  });
}

export function useStartScan(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { scan_type?: string; config?: Record<string, unknown> }) =>
      api.create(projectId, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scans", projectId] }),
  });
}

export function usePauseScan(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (scanId: string) => api.pause(scanId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scans", projectId] }),
  });
}

export function useCancelScan(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (scanId: string) => api.cancel(scanId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scans", projectId] }),
  });
}

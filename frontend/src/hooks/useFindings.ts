"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { findings as api } from "@/lib/api";

interface FindingsFilter {
  severity?: string;
  status?: string;
  page?: number;
  limit?: number;
  sort?: string;
}

export function useFindings(projectId: string, filters: FindingsFilter = {}) {
  return useQuery({
    queryKey: ["findings", projectId, filters],
    queryFn: () => api.list(projectId, filters),
    enabled: !!projectId,
  });
}

export function useFinding(findingId: string) {
  return useQuery({
    queryKey: ["finding", findingId],
    queryFn: () => api.get(findingId),
    enabled: !!findingId,
  });
}

export function useUpdateFinding(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...body }: { id: string; status?: string; notes?: string }) =>
      api.update(id, body),
    onSuccess: (_, { id }) => {
      qc.invalidateQueries({ queryKey: ["findings", projectId] });
      qc.invalidateQueries({ queryKey: ["finding", id] });
    },
  });
}

export function useVerifyFinding(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.verify(id),
    onSuccess: (_, id) => {
      qc.invalidateQueries({ queryKey: ["findings", projectId] });
      qc.invalidateQueries({ queryKey: ["finding", id] });
    },
  });
}

export function useFindingEvidence(findingId: string) {
  return useQuery({
    queryKey: ["evidence", findingId],
    queryFn: () => api.evidence(findingId),
    enabled: !!findingId,
  });
}

import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import type { SeverityLevel } from "@/types";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function severityColor(severity: SeverityLevel): string {
  const map: Record<SeverityLevel, string> = {
    critical: "text-red-500",
    high: "text-orange-500",
    medium: "text-yellow-500",
    low: "text-green-500",
    info: "text-blue-500",
  };
  return map[severity] ?? "text-gray-400";
}

export function severityBadgeClass(severity: SeverityLevel): string {
  const map: Record<SeverityLevel, string> = {
    critical: "bg-red-900 text-red-200 border border-red-700",
    high: "bg-orange-900 text-orange-200 border border-orange-700",
    medium: "bg-yellow-900 text-yellow-200 border border-yellow-700",
    low: "bg-green-900 text-green-200 border border-green-700",
    info: "bg-blue-900 text-blue-200 border border-blue-700",
  };
  return map[severity] ?? "bg-gray-800 text-gray-300";
}

export function formatDate(iso: string): string {
  return new Date(iso).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function truncate(str: string, max = 60): string {
  return str.length > max ? str.slice(0, max) + "…" : str;
}

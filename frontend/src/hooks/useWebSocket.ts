"use client";

import { useEffect, useRef, useCallback } from "react";
import { getValidAccessToken } from "@/lib/auth";
import type { WSScanEvent } from "@/types";

interface UseWebSocketOptions {
  projectId: string;
  onEvent: (event: WSScanEvent) => void;
  enabled?: boolean;
}

export function useWebSocket({ projectId, onEvent, enabled = true }: UseWebSocketOptions) {
  const ws = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const retries = useRef(0);
  const MAX_RETRIES = 8;

  const connect = useCallback(async () => {
    if (!enabled || retries.current >= MAX_RETRIES) return;

    const token = await getValidAccessToken();
    if (!token) return;

    const wsUrl = process.env.NEXT_PUBLIC_WS_URL || `ws://localhost:8000`;
    const url = `${wsUrl}/ws/projects/${projectId}/scan?token=${token}`;

    const socket = new WebSocket(url);
    ws.current = socket;

    socket.onopen = () => {
      retries.current = 0;
    };

    socket.onmessage = (e) => {
      try {
        const event: WSScanEvent = JSON.parse(e.data);
        onEvent(event);
      } catch {
        // ignore malformed
      }
    };

    socket.onclose = (e) => {
      ws.current = null;
      if (!e.wasClean && enabled && retries.current < MAX_RETRIES) {
        const delay = Math.min(1000 * 2 ** retries.current, 30000);
        retries.current++;
        reconnectTimer.current = setTimeout(connect, delay);
      }
    };

    socket.onerror = () => {
      socket.close();
    };
  }, [projectId, onEvent, enabled]);

  useEffect(() => {
    if (!enabled) return;
    connect();

    return () => {
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
      ws.current?.close(1000, "unmounting");
      ws.current = null;
    };
  }, [connect, enabled]);

  const send = useCallback((data: unknown) => {
    if (ws.current?.readyState === WebSocket.OPEN) {
      ws.current.send(JSON.stringify(data));
    }
  }, []);

  return { send };
}

import { useState, useEffect, useCallback } from "react";

const MAX_HISTORY = 3;

export function useInputHistory(storageKey: string) {
  const [history, setHistory] = useState<string[]>([]);

  useEffect(() => {
    try {
      const stored = localStorage.getItem(storageKey);
      if (stored) {
        const parsed = JSON.parse(stored);
        setHistory(parsed.slice(0, MAX_HISTORY));
      }
    } catch (e) {
      console.error("Failed to load history:", e);
    }
  }, [storageKey]);

  const addToHistory = useCallback(
    (input: string) => {
      const trimmed = input.trim();
      if (!trimmed) return;

      setHistory((prev) => {
        const filtered = prev.filter((item) => item !== trimmed);
        const next = [trimmed, ...filtered].slice(0, MAX_HISTORY);
        try {
          localStorage.setItem(storageKey, JSON.stringify(next));
        } catch (e) {
          console.error("Failed to save IP history:", e);
        }
        return next;
      });
    },
    [storageKey],
  );

  const removeFromHistory = useCallback(
    (input: string) => {
      setHistory((prev) => {
        const next = prev.filter((item) => item !== input);
        try {
          localStorage.setItem(storageKey, JSON.stringify(next));
        } catch (e) {
          console.error("Failed to save IP history:", e);
        }
        return next;
      });
    },
    [storageKey],
  );

  return { history, addToHistory, removeFromHistory };
}

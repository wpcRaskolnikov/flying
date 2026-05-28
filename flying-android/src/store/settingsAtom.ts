import { atom } from "jotai";
import { load } from "@tauri-apps/plugin-store";

export const settingsStore = load("settings.json");

function atomWithSettings<T>(key: string, initialValue: T) {
  const base = atom(initialValue);
  return atom(
    (get) => get(base),
    (get, set, update: T | ((prev: T) => T)) => {
      const prev = get(base);
      const next =
        typeof update === "function"
          ? (update as (prev: T) => T)(prev)
          : update;

      set(base, next);
      settingsStore.then((store) => store.set(key, next));
    },
  );
}

export const portAtom = atomWithSettings("port", 3290);

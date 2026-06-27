import { useState, useEffect } from "react";
import { yCollab } from "y-codemirror.next";
import * as Y from "yjs";
import { WebsocketProvider } from "y-websocket";
import { python } from "@codemirror/lang-python";
import { useSnackbar } from "./useSnackbar";

export interface Peer {
  id: number;
  color: string;
  name: string;
}

const USER_COLORS = [
  { color: "#e57373", light: "#e5737333" },
  { color: "#64b5f6", light: "#64b5f633" },
  { color: "#81c784", light: "#81c78433" },
  { color: "#ffb74d", light: "#ffb74d33" },
  { color: "#ba68c8", light: "#ba68c833" },
  { color: "#4dd0e1", light: "#4dd0e133" },
  { color: "#f06292", light: "#f0629233" },
  { color: "#a1887f", light: "#a1887f33" },
];

function pickColor() {
  return USER_COLORS[Math.floor(Math.random() * USER_COLORS.length)];
}

export interface SessionConfig {
  serverUrl: string;
  room: string;
  name: string;
}

export type ConnectionStatus =
  "idle" | "connecting" | "connected" | "disconnected";

export function useYjsCollab(session: SessionConfig | null) {
  const { showSnackbar } = useSnackbar();

  const [peers, setPeers] = useState<Peer[]>([]);
  const [status, setStatus] = useState<ConnectionStatus>("idle");
  const [collabExt, setCollabExt] = useState<ReturnType<typeof yCollab> | null>(
    null,
  );

  const serverUrl = session?.serverUrl ?? "";
  const room = session?.room ?? "";
  const name = session?.name ?? "";

  useEffect(() => {
    setCollabExt(null);
    setPeers([]);
    setStatus(serverUrl && room && name ? "connecting" : "idle");

    if (!serverUrl || !room || !name) return;

    const ydoc = new Y.Doc();
    const ytext = ydoc.getText("codemirror");
    const undoManager = new Y.UndoManager(ytext);

    const uc = pickColor();
    const provider = new WebsocketProvider(serverUrl, room, ydoc);
    provider.awareness.setLocalStateField("user", {
      name,
      color: uc.color,
      colorLight: uc.light,
    });

    const ext = yCollab(ytext, provider.awareness, { undoManager });
    setCollabExt(ext);

    const updatePeers = () => {
      const states = provider.awareness.getStates();
      const list: Peer[] = [];
      const localId = provider.awareness.clientID;
      states.forEach((state: any, clientId: number) => {
        if (clientId !== localId) {
          const u = state.user || { name: "Anonymous", color: "#999" };
          list.push({ id: clientId, color: u.color, name: u.name });
        }
      });
      setPeers(list);
    };

    let timeout = setTimeout(() => {
      setStatus("disconnected");
      showSnackbar(`Connection to ${serverUrl} timed out`, "error");
      provider.destroy();
    }, 5000);

    const handleStatus = ({ status }: { status: string }) => {
      if (status === "connected") {
        clearTimeout(timeout);
        setStatus("connected");
        showSnackbar(`Joined "${room}"`, "success");
      } else if (status === "disconnected") {
        setStatus("disconnected");
        showSnackbar("Connection lost, retrying...", "error");
      }
    };

    provider.on("status", handleStatus);
    provider.awareness.on("change", updatePeers);
    updatePeers();

    return () => {
      clearTimeout(timeout);
      provider.off("status", handleStatus);
      provider.awareness.off("change", updatePeers);
      provider.destroy();
      undoManager.destroy();
      ydoc.destroy();
    };
  }, [serverUrl, room, name, showSnackbar]);

  return {
    peers,
    status,
    extensions: collabExt ? [python(), collabExt] : [],
  };
}

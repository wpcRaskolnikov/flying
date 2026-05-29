import { useState, useRef, useEffect, useCallback } from "react";
import {
  Box,
  Button,
  Stack,
  TextField,
  Typography,
  Chip,
  Avatar,
  List,
  ListItem,
  ListItemAvatar,
  ListItemText,
  IconButton,
  Select,
  Switch,
  MenuItem,
  InputLabel,
  FormControl,
  Alert,
} from "@mui/material";
import {
  Group as GroupIcon,
  ContentCopy as CopyIcon,
  Stop as StopIcon,
  Wifi as WifiIcon,
} from "@mui/icons-material";
import CodeMirror from "@uiw/react-codemirror";
import { yCollab } from "y-codemirror.next";
import * as Y from "yjs";
import { WebsocketProvider } from "y-websocket";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { invoke } from "@tauri-apps/api/core";
import { useSnackbar } from "../hooks";

interface Peer {
  id: number;
  color: string;
  name: string;
}

type ServerState =
  | { status: "idle" }
  | { status: "starting" }
  | { status: "running" };

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

const DEFAULT_PORT = 18080;

function CollabEditPage() {
  const [roomName, setRoomName] = useState("");
  const [userName, setUserName] = useState("");
  const [serverAddr, setServerAddr] = useState("");
  const [useWss, setUseWss] = useState(false);
  const [peers, setPeers] = useState<Peer[]>([]);
  const [inRoom, setInRoom] = useState(false);
  const [connected, setConnected] = useState(false);
  const { showSnackbar } = useSnackbar();

  // Local server state
  const [serverState, setServerState] = useState<ServerState>({ status: "idle" });

  const ydocRef = useRef<Y.Doc | null>(null);
  const providerRef = useRef<WebsocketProvider | null>(null);
  const undoRef = useRef<Y.UndoManager | null>(null);
  const collabExtRef = useRef<any>(null);
  const [editorExtensions, setEditorExtensions] = useState<any[]>([]);

  // Persistent refs for event handlers so they can be reliably removed
  const handleStatusRef = useRef<((data: { status: string }) => void) | null>(
    null,
  );
  const updatePeersRef = useRef<(() => void) | null>(null);

  // Poll local server status
  useEffect(() => {
    let isMounted = true;
    const checkStatus = async () => {
      try {
        const s = await invoke<ServerState>("get_collab_server_status");
        if (isMounted) {
          setServerState(s);
        }
      } catch {
        // ignore
      }
    };
    checkStatus();
    const interval = setInterval(checkStatus, 2000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const handleToggleServer = async () => {
    if (serverState.status === "running") {
      try {
        await invoke("stop_collab_server");
        setServerState({ status: "idle" });
        notify("Local server stopped", "info");
      } catch (e: any) {
        notify(`Failed to stop server: ${e}`, "error");
      }
    } else {
      setServerState({ status: "starting" });
      try {
        const result = await invoke("start_collab_server", {
          port: DEFAULT_PORT,
        });
        setServerState({ status: "running" });
        setServerAddr(`127.0.0.1:${DEFAULT_PORT}`);
        setUseWss(false);
        notify(result as string, "success");
      } catch (e: any) {
        notify(`Failed to start server: ${e}`, "error");
        setServerState({ status: "idle" });
      }
    }
  };

  const notify = useCallback(
    (message: string, severity: "success" | "error" | "info" = "info") => {
      showSnackbar(message, severity);
    },
    [],
  );

  const handleJoinRoom = () => {
    if (!roomName.trim()) {
      notify("Please enter a room name", "error");
      return;
    }
    if (!userName.trim()) {
      notify("Please enter your name", "error");
      return;
    }
    if (!serverAddr.trim()) {
      notify("Please enter server address", "error");
      return;
    }

    const ydoc = new Y.Doc();
    ydocRef.current = ydoc;

    const ytext = ydoc.getText("codemirror");
    const undoManager = new Y.UndoManager(ytext);
    undoRef.current = undoManager;

    const uc = pickColor();
    const protocol = useWss ? "wss" : "ws";
    const serverUrl = `${protocol}://${serverAddr.trim()}`;

    notify(`Connecting to ${serverUrl}`, "info");

    const provider = new WebsocketProvider(serverUrl, roomName.trim(), ydoc);
    providerRef.current = provider;

    provider.awareness.setLocalStateField("user", {
      name: userName.trim(),
      color: uc.color,
      colorLight: uc.light,
    });

    collabExtRef.current = yCollab(ytext, provider.awareness, {
      undoManager,
    });
    setEditorExtensions([collabExtRef.current]);

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
    updatePeersRef.current = updatePeers;

    // Wait for connection before entering editor
    const handleStatus = ({ status }: { status: string }) => {
      if (status === "connected") {
        setConnected(true);
        setInRoom(true);
        notify(`Joined "${roomName}"`, "success");
      } else if (status === "disconnected") {
        setConnected(false);
        notify("Connection lost, retrying...", "error");
      }
    };
    handleStatusRef.current = handleStatus;

    provider.on("status", handleStatus);
    provider.awareness.on("change", updatePeers);
    updatePeers();
  };

  const handleLeaveRoom = () => {
    if (providerRef.current) {
      // Remove event listeners before destroying to prevent memory leaks
      if (handleStatusRef.current) {
        providerRef.current.off("status", handleStatusRef.current);
      }
      if (providerRef.current.awareness && updatePeersRef.current) {
        providerRef.current.awareness.off("change", updatePeersRef.current);
      }
      providerRef.current.destroy();
      providerRef.current = null;
    }
    if (undoRef.current) {
      undoRef.current.destroy();
      undoRef.current = null;
    }
    if (ydocRef.current) {
      ydocRef.current.destroy();
      ydocRef.current = null;
    }
    collabExtRef.current = null;
    setEditorExtensions([]);
    setConnected(false);
    setPeers([]);
    setInRoom(false);
    handleStatusRef.current = null;
    updatePeersRef.current = null;
    notify("Left the room", "info");
  };

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (providerRef.current) {
        if (handleStatusRef.current) {
          providerRef.current.off("status", handleStatusRef.current);
        }
        if (providerRef.current.awareness && updatePeersRef.current) {
          providerRef.current.awareness.off("change", updatePeersRef.current);
        }
        providerRef.current.destroy();
      }
      if (ydocRef.current) ydocRef.current.destroy();
      if (undoRef.current) undoRef.current.destroy();
    };
  }, []);

  const handleCopyRoomName = async () => {
    await writeText(roomName);
    notify("Room name copied", "success");
  };

  const handleCreateRoom = () => {
    setRoomName(`room-${Math.random().toString(36).substring(2, 8)}`);
  };

  // --- Join screen ---
  if (!inRoom) {
    return (
      <Stack spacing={2} sx={{ width: "100%" }}>
        <Typography variant="h6">Collaborative Editor</Typography>
        <Typography variant="body2" color="text.secondary">
          Enter a server address and room to start editing together.
        </Typography>

        {/* Local server toggle */}
        <Box
          sx={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <Typography variant="body2" color="text.secondary">
            Local Collaboration Server
          </Typography>
          {serverState.status === "starting" ? (
            <Chip size="small" label="Starting..." color="warning" />
          ) : (
            <Switch
              checked={serverState.status === "running"}
              onChange={handleToggleServer}
              color="success"
              size="small"
            />
          )}
        </Box>
        {serverState.status === "running" && (
          <Alert severity="success">
            Server running on ws://0.0.0.0:{DEFAULT_PORT}
          </Alert>
        )}

        <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
          <Box sx={{ display: "flex", gap: 1, alignItems: "center" }}>
            <FormControl size="small" sx={{ minWidth: 90 }}>
              <InputLabel>Protocol</InputLabel>
              <Select
                value={useWss ? "wss" : "ws"}
                label="Protocol"
                onChange={(e) => setUseWss(e.target.value === "wss")}
              >
                <MenuItem value="ws">ws://</MenuItem>
                <MenuItem value="wss">wss://</MenuItem>
              </Select>
            </FormControl>
            <TextField
              fullWidth
              label="Server Address"
              value={serverAddr}
              onChange={(e) => setServerAddr(e.target.value)}
              placeholder="e.g., 192.168.1.10:8080 or demos.yjs.dev"
            />
          </Box>

          <Box sx={{ display: "flex", gap: 1, alignItems: "center" }}>
            <TextField
              fullWidth
              label="Room Name"
              value={roomName}
              onChange={(e) => setRoomName(e.target.value)}
              placeholder="Enter or create a room"
            />
            <Button variant="outlined" onClick={handleCreateRoom} size="large">
              Generate
            </Button>
          </Box>

          <TextField
            label="Your Name"
            value={userName}
            onChange={(e) => setUserName(e.target.value)}
            placeholder="How others will see you"
          />

          <Button
            variant="contained"
            size="large"
            startIcon={<WifiIcon />}
            onClick={handleJoinRoom}
            fullWidth
          >
            JOIN ROOM
          </Button>
        </Box>
      </Stack>
    );
  }

  // --- editor screen ---
  return (
    <Stack
      sx={{
        display: "flex",
        flexDirection: "column",
        height: "100vh",
        pb: 7,
      }}
    >
      {/* Header */}
      <Box
        sx={{
          p: 1.5,
          borderBottom: "1px solid",
          borderColor: "divider",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          bgcolor: "background.paper",
          flexShrink: 0,
        }}
      >
        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <Chip
            size="small"
            icon={<GroupIcon />}
            label={`${peers.length + 1} online`}
            color={connected ? "success" : "default"}
            variant="outlined"
          />
          <Chip
            size="small"
            label={connected ? "Connected" : "Connecting..."}
            color={connected ? "success" : "warning"}
          />
          <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
            <Typography variant="body2" noWrap sx={{ maxWidth: 120 }}>
              {roomName}
            </Typography>
            <IconButton size="small" onClick={handleCopyRoomName}>
              <CopyIcon fontSize="small" />
            </IconButton>
          </Box>
        </Box>
        <Button
          size="small"
          color="error"
          variant="outlined"
          startIcon={<StopIcon />}
          onClick={handleLeaveRoom}
        >
          Leave
        </Button>
      </Box>

      {/* Peers */}
      {peers.length > 0 && (
        <Box
          sx={{
            px: 1.5,
            py: 0.5,
            borderBottom: "1px solid",
            borderColor: "divider",
            bgcolor: "background.paper",
            flexShrink: 0,
          }}
        >
          <List dense disablePadding>
            {peers.map((peer) => (
              <ListItem key={peer.id} disablePadding sx={{ py: 0.25 }}>
                <ListItemAvatar sx={{ minWidth: 36 }}>
                  <Avatar
                    sx={{
                      width: 24,
                      height: 24,
                      bgcolor: peer.color,
                      fontSize: 12,
                    }}
                  >
                    {peer.name.charAt(0).toUpperCase()}
                  </Avatar>
                </ListItemAvatar>
                <ListItemText
                  primary={peer.name}
                  slotProps={{ primary: { variant: "body2" } }}
                />
              </ListItem>
            ))}
          </List>
        </Box>
      )}

      {/* Editor */}
      <Box sx={{ flexGrow: 1, overflow: "hidden" }}>
        <CodeMirror
          extensions={editorExtensions}
          height="100%"
          theme="light"
          basicSetup
        />
      </Box>
    </Stack>
  );
}

export default CollabEditPage;
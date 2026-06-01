import { useState, useRef, useEffect, useCallback, useMemo } from "react";
import {
  Box,
  Stack,
  TextField,
  Typography,
  Button,
  Chip,
  Avatar,
  AvatarGroup,
  IconButton,
  Select,
  Switch,
  MenuItem,
  InputLabel,
  FormControl,
  Alert,
  AppBar,
  Toolbar,
  Tooltip,
  CircularProgress,
} from "@mui/material";
import {
  Group as GroupIcon,
  ContentCopy as CopyIcon,
  Stop as StopIcon,
  Wifi as WifiIcon,
  Autorenew as AutorenewIcon,
  Person as PersonIcon,
} from "@mui/icons-material";
import CodeMirror from "@uiw/react-codemirror";
import { yCollab } from "y-codemirror.next";
import * as Y from "yjs";
import { WebsocketProvider } from "y-websocket";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { invoke } from "@tauri-apps/api/core";
import { useSnackbar } from "../hooks";
import { predicates, objects } from "friendly-words";

interface Peer {
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

const DEFAULT_PORT = 18080;

function useYjsCollab() {
  const { showSnackbar } = useSnackbar();

  const ydocRef = useRef<Y.Doc | null>(null);
  const providerRef = useRef<WebsocketProvider | null>(null);
  const undoRef = useRef<Y.UndoManager | null>(null);
  const collabExtRef = useRef<any>(null);
  const handleStatusRef = useRef<((data: { status: string }) => void) | null>(
    null,
  );
  const updatePeersRef = useRef<(() => void) | null>(null);

  const [peers, setPeers] = useState<Peer[]>([]);
  const [connected, setConnected] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const [currentRoom, setCurrentRoom] = useState("");
  const [version, setVersion] = useState(0);
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const clearConnectTimeout = useCallback(() => {
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
      timeoutRef.current = null;
    }
  }, []);

  const cleanup = useCallback(() => {
    clearConnectTimeout();
    const provider = providerRef.current;
    if (provider) {
      if (handleStatusRef.current)
        provider.off("status", handleStatusRef.current);
      if (updatePeersRef.current)
        provider.awareness.off("change", updatePeersRef.current);
      provider.destroy();
      providerRef.current = null;
    }
    undoRef.current?.destroy();
    undoRef.current = null;
    ydocRef.current?.destroy();
    ydocRef.current = null;
    collabExtRef.current = null;
    handleStatusRef.current = null;
    updatePeersRef.current = null;
    setPeers([]);
    setConnected(false);
    setConnecting(false);
    setCurrentRoom("");
  }, [clearConnectTimeout]);

  // Unmount cleanup
  useEffect(() => {
    return () => {
      providerRef.current?.destroy();
      undoRef.current?.destroy();
      ydocRef.current?.destroy();
    };
  }, []);

  const joinRoom = useCallback(
    (serverUrl: string, room: string, name: string) => {
      // Kill any existing connection before creating a new one
      cleanup();

      const ydoc = new Y.Doc();
      ydocRef.current = ydoc;

      const ytext = ydoc.getText("codemirror");
      const undoManager = new Y.UndoManager(ytext);
      undoRef.current = undoManager;

      const uc = pickColor();
      const provider = new WebsocketProvider(serverUrl, room, ydoc);
      providerRef.current = provider;

      provider.awareness.setLocalStateField("user", {
        name,
        color: uc.color,
        colorLight: uc.light,
      });

      collabExtRef.current = yCollab(ytext, provider.awareness, {
        undoManager,
      });

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

      const handleStatus = ({ status }: { status: string }) => {
        if (status === "connected") {
          clearConnectTimeout();
          setConnected(true);
          setConnecting(false);
          setCurrentRoom(room);
          showSnackbar(`Joined "${room}"`, "success");
        } else if (status === "disconnected") {
          setConnected(false);
          showSnackbar("Connection lost, retrying...", "error");
        }
      };
      handleStatusRef.current = handleStatus;

      provider.on("status", handleStatus);
      provider.awareness.on("change", updatePeers);
      updatePeers();

      // Timeout if connection doesn't succeed within 5s
      setConnecting(true);
      timeoutRef.current = setTimeout(() => {
        showSnackbar(`Connection to ${serverUrl} timed out`, "error");
        cleanup();
      }, 5000);

      // Bump version to force CodeMirror remount with new collab extension
      setVersion((v) => v + 1);
    },
    [cleanup],
  );

  const leaveRoom = useCallback(() => {
    cleanup();
    showSnackbar("Left the room", "info");
  }, [cleanup]);

  const editorExtensions = useMemo(
    () => (collabExtRef.current ? [collabExtRef.current] : []),
    [version],
  );

  return {
    peers,
    connected,
    connecting,
    currentRoom,
    editorExtensions,
    editorKey: version,
    joinRoom,
    leaveRoom,
  };
}

function CollabEditPage() {
  const [isServerRunning, setIsServerRunning] = useState(false);
  const [roomName, setRoomName] = useState("");
  const [userName, setUserName] = useState("");
  const [serverAddr, setServerAddr] = useState("");
  const [useWss, setUseWss] = useState(false);
  const { showSnackbar } = useSnackbar();

  const {
    peers,
    connected,
    connecting,
    currentRoom,
    editorExtensions,
    editorKey,
    joinRoom,
    leaveRoom,
  } = useYjsCollab();

  const inRoom = currentRoom !== "";

  const handleToggleServer = async () => {
    if (isServerRunning) {
      try {
        await invoke("stop_collab_server");
        setIsServerRunning(false);
        showSnackbar("Local server stopped", "info");
      } catch (e: any) {
        showSnackbar(`Failed to stop server: ${e}`, "error");
      }
    } else {
      try {
        await invoke("start_collab_server", { port: DEFAULT_PORT });
        setIsServerRunning(true);
        setServerAddr(`127.0.0.1:${DEFAULT_PORT}`);
        setUseWss(false);
        showSnackbar("Local server started", "success");
      } catch (e: any) {
        showSnackbar(`Failed to start server: ${e}`, "error");
        setIsServerRunning(false);
      }
    }
  };

  const handleJoinRoom = () => {
    if (!serverAddr.trim()) {
      showSnackbar("Please enter server address", "error");
      return;
    }
    if (!roomName.trim()) {
      showSnackbar("Please enter a room name", "error");
      return;
    }
    if (!userName.trim()) {
      showSnackbar("Please enter your name", "error");
      return;
    }

    const protocol = useWss ? "wss" : "ws";
    joinRoom(
      `${protocol}://${serverAddr.trim()}`,
      roomName.trim(),
      userName.trim(),
    );
  };

  const handleCopyRoomName = async () => {
    await writeText(currentRoom);
    showSnackbar("Room name copied", "success");
  };

  const generateRoomName = () => {
    const pick = (arr: string[]) => arr[Math.floor(Math.random() * arr.length)];
    setRoomName(`${pick(predicates)}-${pick(objects)}`.toLowerCase());
    showSnackbar("Room name generated", "success");
  };

  // --- Join screen ---
  if (!inRoom) {
    return (
      <Stack spacing={2}>
        <Typography variant="h6">Collaborative Editor</Typography>

        <Box
          sx={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <Typography variant="body2" color="text.secondary">
            Start Local Collaboration Server
          </Typography>
          <Switch
            checked={isServerRunning}
            onChange={handleToggleServer}
            color="success"
            size="small"
          />
        </Box>
        {isServerRunning && (
          <Alert severity="success">
            Server running on ws://0.0.0.0:{DEFAULT_PORT}
          </Alert>
        )}

        <Box sx={{ display: "flex", gap: 1, alignItems: "center" }}>
          <FormControl size="small" sx={{ minWidth: 95 }}>
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

        <Box sx={{ display: "flex", gap: 1 }}>
          <TextField
            fullWidth
            label="Room Name"
            placeholder="Enter or create a room"
            value={roomName}
            onChange={(e) => setRoomName(e.target.value)}
          />
          <IconButton
            onClick={generateRoomName}
            color="primary"
            title="Generate room name"
          >
            <AutorenewIcon />
          </IconButton>
          <IconButton
            onClick={handleCopyRoomName}
            color="primary"
            title="Copy room name"
          >
            <CopyIcon />
          </IconButton>
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
          startIcon={connecting ? <CircularProgress size={20} color="inherit" /> : <WifiIcon />}
          onClick={handleJoinRoom}
          fullWidth
          disabled={connecting}
        >
          {connecting ? "Connecting..." : "JOIN ROOM"}
        </Button>
      </Stack>
    );
  }

  // --- Editor screen ---
  return (
    <Stack sx={{ pb: 2 }}>
      <AppBar
        position="static"
        color="inherit"
        elevation={0}
        sx={{ borderBottom: "1px solid", borderColor: "divider" }}
      >
        <Toolbar variant="dense">
          <Chip
            size="small"
            icon={<GroupIcon />}
            label={`${peers.length + 1}`}
            color={connected ? "success" : "default"}
            variant="outlined"
            sx={{ mr: 1 }}
          />
          <Box sx={{ display: "flex", alignItems: "center", mr: 1 }}>
            <Typography variant="body2" noWrap sx={{ maxWidth: 120 }}>
              {currentRoom}
            </Typography>
            <Tooltip title="Copy room name">
              <IconButton size="small" onClick={handleCopyRoomName}>
                <CopyIcon fontSize="small" />
              </IconButton>
            </Tooltip>
            {userName && (
              <Tooltip title={`${userName} (You)`} placement="bottom">
                <Avatar
                  sx={{
                    width: 28,
                    height: 28,
                    bgcolor: "#666",
                    fontSize: 12,
                    ml: 0.5,
                  }}
                >
                  {userName.charAt(0).toUpperCase()}
                </Avatar>
              </Tooltip>
            )}
          </Box>
          <Box sx={{ flexGrow: 1 }} />
          {peers.length > 0 && (
            <AvatarGroup
              max={4}
              slotProps={{
                additionalAvatar: {
                  sx: { width: 28, height: 28, fontSize: 12 },
                  children: <PersonIcon sx={{ fontSize: 12 }} />,
                },
              }}
            >
              {peers.map((peer) => (
                <Tooltip key={peer.id} title={peer.name} placement="bottom">
                  <Avatar
                    sx={{
                      width: 28,
                      height: 28,
                      bgcolor: peer.color,
                      fontSize: 12,
                    }}
                  >
                    {peer.name.charAt(0).toUpperCase()}
                  </Avatar>
                </Tooltip>
              ))}
            </AvatarGroup>
          )}
          <Button
            size="small"
            color="error"
            variant="outlined"
            startIcon={<StopIcon />}
            onClick={leaveRoom}
          >
            Leave
          </Button>
        </Toolbar>
      </AppBar>

      {/* Editor */}
      <Box sx={{ flexGrow: 1, overflow: "hidden" }}>
        <CodeMirror
          key={editorKey}
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

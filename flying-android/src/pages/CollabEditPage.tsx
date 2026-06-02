import { useState, useEffect, useMemo } from "react";
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
  Stop as StopIcon,
  Wifi as WifiIcon,
  ContentCopy as CopyIcon,
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

interface SessionConfig {
  serverUrl: string;
  room: string;
  name: string;
}

function useYjsCollab(session: SessionConfig | null) {
  const { showSnackbar } = useSnackbar();

  const [peers, setPeers] = useState<Peer[]>([]);
  const [connected, setConnected] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const [collabExt, setCollabExt] = useState<ReturnType<typeof yCollab> | null>(
    null,
  );
  const extensions = useMemo(() => (collabExt ? [collabExt] : []), [collabExt]);

  useEffect(() => {
    // Reset UI state on every session change (including disconnect).
    setCollabExt(null);
    setPeers([]);
    setConnected(false);
    setConnecting(false);

    // No active session — nothing to connect to.
    if (!session) return;

    const { serverUrl, room, name } = session;
    setConnecting(true);

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

    const handleStatus = ({ status }: { status: string }) => {
      clearTimeout(timeout);
      if (status === "connected") {
        setConnected(true);
        setConnecting(false);
        showSnackbar(`Joined "${room}"`, "success");
      } else if (status === "disconnected") {
        setConnected(false);
        showSnackbar("Connection lost, retrying...", "error");
      }
    };

    const timeout = setTimeout(() => {
      showSnackbar(`Connection to ${serverUrl} timed out`, "error");
      provider.destroy();
    }, 5000);
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
  }, [session, showSnackbar]);

  return { peers, connected, connecting, extensions };
}

function CollabEditPage() {
  const [isServerRunning, setIsServerRunning] = useState(false);
  const [roomName, setRoomName] = useState("");
  const [userName, setUserName] = useState("");
  const [serverAddr, setServerAddr] = useState("");
  const [useWss, setUseWss] = useState(false);
  const [activeSession, setActiveSession] = useState<SessionConfig | null>(
    null,
  );
  const { showSnackbar } = useSnackbar();

  const { peers, connected, connecting, extensions } =
    useYjsCollab(activeSession);
  const currentRoom = activeSession?.room ?? "";
  const inRoom = activeSession !== null;

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
    setActiveSession({
      serverUrl: `${protocol}://${serverAddr.trim()}`,
      room: roomName.trim(),
      name: userName.trim(),
    });
  };

  const handleLeaveRoom = () => {
    setActiveSession(null);
    showSnackbar("Left the room", "info");
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
          startIcon={
            connecting ? (
              <CircularProgress size={20} color="inherit" />
            ) : (
              <WifiIcon />
            )
          }
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
            {activeSession?.name && (
              <Tooltip
                title={`${activeSession?.name} (You)`}
                placement="bottom"
              >
                <Avatar
                  sx={{
                    width: 28,
                    height: 28,
                    bgcolor: "#666",
                    fontSize: 12,
                    ml: 0.5,
                  }}
                >
                  {activeSession?.name.charAt(0).toUpperCase()}
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
            onClick={handleLeaveRoom}
          >
            Leave
          </Button>
        </Toolbar>
      </AppBar>

      {/* Editor */}
      <Box sx={{ flexGrow: 1, overflow: "hidden" }}>
        <CodeMirror
          key={currentRoom}
          extensions={extensions}
          height="100%"
          theme="light"
          basicSetup
        />
      </Box>
    </Stack>
  );
}

export default CollabEditPage;

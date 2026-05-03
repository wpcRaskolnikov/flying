import { useState, useRef, useEffect, useCallback } from "react";
import {
  Box,
  Button,
  TextField,
  Typography,
  Chip,
  Avatar,
  List,
  ListItem,
  ListItemAvatar,
  ListItemText,
  IconButton,
  Snackbar,
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

function CollabEditPage() {
  const [roomName, setRoomName] = useState("");
  const [userName, setUserName] = useState("");
  const [serverAddr, setServerAddr] = useState("demos.yjs.dev");
  const [peers, setPeers] = useState<Peer[]>([]);
  const [inRoom, setInRoom] = useState(false);
  const [connected, setConnected] = useState(false);
  const [snackbar, setSnackbar] = useState({
    open: false,
    message: "",
    severity: "success" as "success" | "error" | "info",
  });

  const ydocRef = useRef<Y.Doc | null>(null);
  const providerRef = useRef<WebsocketProvider | null>(null);
  const undoRef = useRef<Y.UndoManager | null>(null);
  const collabExtRef = useRef<any>(null);

  const notify = useCallback(
    (message: string, severity: "success" | "error" | "info" = "info") => {
      setSnackbar({ open: true, message, severity });
    },
    []
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
    const protocol = serverAddr.includes("localhost") ? "ws" : "wss";
    const wsUrl = `${protocol}://${serverAddr.trim()}/${roomName.trim()}`;

    const provider = new WebsocketProvider(wsUrl, roomName.trim(), ydoc);
    providerRef.current = provider;

    provider.awareness.setLocalStateField("user", {
      name: userName.trim(),
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

    provider.on("status", ({ status }: { status: string }) => {
      setConnected(status === "connected");
    });

    provider.awareness.on("change", updatePeers);
    updatePeers();

    setInRoom(true);
    notify(`Joined "${roomName}"`, "success");
  };

  const handleLeaveRoom = () => {
    if (providerRef.current) {
      providerRef.current.destroy();
      providerRef.current = null;
    }
    if (ydocRef.current) {
      ydocRef.current.destroy();
      ydocRef.current = null;
    }
    undoRef.current = null;
    collabExtRef.current = null;
    setConnected(false);
    setPeers([]);
    setInRoom(false);
    notify("Left the room", "info");
  };

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (providerRef.current) providerRef.current.destroy();
      if (ydocRef.current) ydocRef.current.destroy();
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
      <Box sx={{ p: 2, pt: 3 }}>
        <Typography variant="h6" sx={{ mb: 3 }}>
          Collaborative Editor
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          Enter a server address and room to start editing together.
        </Typography>

        <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
          <TextField
            label="Server Address"
            value={serverAddr}
            onChange={(e) => setServerAddr(e.target.value)}
            placeholder="e.g., demos.yjs.dev or 192.168.1.10:8080"
          />

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

        <Snackbar
          open={snackbar.open}
          autoHideDuration={3000}
          onClose={() => setSnackbar({ ...snackbar, open: false })}
          anchorOrigin={{ vertical: "bottom", horizontal: "center" }}
          sx={{ bottom: 72 }}
        >
          <Alert severity={snackbar.severity} sx={{ width: "100%" }}>
            {snackbar.message}
          </Alert>
        </Snackbar>
      </Box>
    );
  }

  // --- Editor screen ---
  return (
    <Box
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
          extensions={collabExtRef.current ? [collabExtRef.current] : []}
          height="100%"
          theme="light"
          basicSetup
        />
      </Box>

      <Snackbar
        open={snackbar.open}
        autoHideDuration={3000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
        anchorOrigin={{ vertical: "bottom", horizontal: "center" }}
        sx={{ bottom: 72 }}
      >
        <Alert severity={snackbar.severity} sx={{ width: "100%" }}>
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
}

export default CollabEditPage;

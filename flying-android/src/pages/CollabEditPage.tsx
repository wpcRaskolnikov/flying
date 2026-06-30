import { useState } from "react";
import {
  Autocomplete,
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
  Delete as DeleteIcon,
} from "@mui/icons-material";
import CodeMirror from "@uiw/react-codemirror";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { invoke } from "@tauri-apps/api/core";
import { useSnackbar, useYjsCollab, useInputHistory } from "../hooks";
import type { SessionConfig } from "../hooks";
import { predicates, objects } from "friendly-words";

const DEFAULT_PORT = 18080;

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
  const serverAddrHistory = useInputHistory("collab-serverAddr");

  const { peers, status, extensions } = useYjsCollab(activeSession);
  const currentRoom = activeSession?.room ?? "";
  const inRoom = status === "connected";

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
    serverAddrHistory.addToHistory(serverAddr);
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
    if (!currentRoom) return;
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
          <Autocomplete
            freeSolo
            options={serverAddrHistory.history}
            value={serverAddr}
            onInputChange={(_, newValue) => setServerAddr(newValue)}
            sx={{ flexGrow: 1 }}
            renderOption={(props, option) => (
              <Box
                component="li"
                {...props}
                key={option}
                sx={{ display: "flex", alignItems: "center" }}
              >
                <span style={{ flexGrow: 1 }}>{option}</span>
                <IconButton
                  size="small"
                  onClick={(e) => {
                    e.stopPropagation();
                    serverAddrHistory.removeFromHistory(option);
                  }}
                >
                  <DeleteIcon fontSize="small" />
                </IconButton>
              </Box>
            )}
            renderInput={(params) => (
              <TextField
                {...params}
                fullWidth
                label="Server Address"
                placeholder="e.g., 192.168.1.10:8080 or demos.yjs.dev"
              />
            )}
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
            status === "connecting" ? (
              <CircularProgress size={20} color="inherit" />
            ) : (
              <WifiIcon />
            )
          }
          onClick={handleJoinRoom}
          fullWidth
          disabled={status === "connecting"}
        >
          {status === "connecting" ? "Connecting..." : "JOIN ROOM"}
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
            color="success"
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
      <Box sx={{ flexGrow: 1, overflow: "visible" }}>
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

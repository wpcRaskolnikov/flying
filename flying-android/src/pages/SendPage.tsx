import { useState, useEffect } from "react";
import {
  Box,
  Button,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Typography,
  LinearProgress,
  Snackbar,
  Alert,
  IconButton,
} from "@mui/material";
import {
  InsertDriveFile as FileIcon,
  Send as SendIcon,
  ContentCopy as CopyIcon,
  Folder as FolderIcon,
  Refresh as RefreshIcon,
  Stop as StopIcon,
} from "@mui/icons-material";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { Store } from "@tauri-apps/plugin-store";

type ConnectionMode = "listen" | "connect" | "relay_listen" | "relay_dial";

function SendPage() {
  const [selectedFile, setSelectedFile] = useState<string>("");
  const [selectedFileName, setSelectedFileName] = useState<string>("");
  const [password, setPassword] = useState("");
  const [connectionMode, setConnectionMode] =
    useState<ConnectionMode>("connect");
  const [connectIp, setConnectIp] = useState("");
  const [relayAddr, setRelayAddr] = useState("");
  const [remotePeerId, setRemotePeerId] = useState("");
  const [peerId, setPeerId] = useState("");
  const [isSending, setIsSending] = useState(false);
  const [status, setStatus] = useState("");
  const [progress, setProgress] = useState(0);
  const [snackbar, setSnackbar] = useState({
    open: false,
    message: "",
    severity: "success" as "success" | "error",
  });

  useEffect(() => {
    const unlisten1 = listen("send-start", () => {
      setIsSending(true);
      setStatus("Sending file...");
      setProgress(0);
    });

    const unlisten2 = listen("send-complete", () => {
      setIsSending(false);
      setStatus("Send completed!");
      setProgress(100);
      setSnackbar({
        open: true,
        message: "File sent successfully",
        severity: "success",
      });
      setTimeout(() => {
        setStatus("");
        setProgress(0);
      }, 2000);
    });

    const unlisten3 = listen<string>("send-error", (event) => {
      setIsSending(false);
      setStatus("");
      setProgress(0);
      setSnackbar({ open: true, message: event.payload, severity: "error" });
    });

    const unlisten4 = listen<number>("send-progress", (event) => {
      setProgress(event.payload);
      setStatus(`Sending file... ${event.payload}%`);
    });

    const unlisten5 = listen<string>("send-ready", (event) => {
      setPeerId(event.payload);
    });

    return () => {
      unlisten1.then((fn) => fn());
      unlisten2.then((fn) => fn());
      unlisten3.then((fn) => fn());
      unlisten4.then((fn) => fn());
      unlisten5.then((fn) => fn());
    };
  }, []);

  const handleFileSelect = async () => {
    try {
      const result = await invoke<[string, string] | null>("pick_file");

      if (result) {
        const [uri, filename] = result;
        setSelectedFile(uri);
        setSelectedFileName(filename);
      }
    } catch (error) {
      console.error("Failed to select file:", error);
      setSnackbar({
        open: true,
        message: "Failed to select file",
        severity: "error",
      });
    }
  };

  const handleFolderSelect = async () => {
    try {
      const result = await invoke<[string, string] | null>("pick_folder");

      if (result) {
        const [uri, foldername] = result;
        setSelectedFile(uri);
        setSelectedFileName(foldername);
      }
    } catch (error) {
      console.error("Failed to select folder:", error);
      setSnackbar({
        open: true,
        message: "Failed to select folder",
        severity: "error",
      });
    }
  };

  const handleCopyPassword = async () => {
    if (password) {
      await writeText(password);
      setSnackbar({
        open: true,
        message: "Password copied to clipboard",
        severity: "success",
      });
    }
  };

  const handleGeneratePassword = async () => {
    try {
      const generatedPassword = await invoke<string>("generate_password");
      setPassword(generatedPassword);
      setSnackbar({
        open: true,
        message: "Password generated",
        severity: "success",
      });
    } catch (error) {
      console.error("Failed to generate password:", error);
      setSnackbar({
        open: true,
        message: "Failed to generate password",
        severity: "error",
      });
    }
  };

  const handleSend = async () => {
    if (!selectedFile) {
      setSnackbar({
        open: true,
        message: "Please select a file",
        severity: "error",
      });
      return;
    }

    if (connectionMode === "connect" && !connectIp.trim()) {
      setSnackbar({
        open: true,
        message: "Please enter target IP address",
        severity: "error",
      });
      return;
    }

    if (
      (connectionMode === "relay_listen" || connectionMode === "relay_dial") &&
      !relayAddr.trim()
    ) {
      setSnackbar({
        open: true,
        message: "Please enter relay address",
        severity: "error",
      });
      return;
    }

    if (connectionMode === "relay_dial" && !remotePeerId.trim()) {
      setSnackbar({
        open: true,
        message: "Please enter remote peer ID",
        severity: "error",
      });
      return;
    }

    let sendPassword = password.trim();

    // Auto-generate password in listen mode if not provided
    if (
      (connectionMode === "listen" || connectionMode === "relay_listen") &&
      !sendPassword
    ) {
      try {
        sendPassword = await invoke<string>("generate_password");
        setPassword(sendPassword);
      } catch (error) {
        console.error("Failed to generate password:", error);
        setSnackbar({
          open: true,
          message: "Failed to generate password",
          severity: "error",
        });
        return;
      }
    }

    if (!sendPassword) {
      setSnackbar({
        open: true,
        message: "Please enter or generate a password",
        severity: "error",
      });
      return;
    }

    try {
      const store = await Store.load("settings.json");
      let port = await store.get<number>("port");
      if (!port) port = 3290;
      await invoke("send_file", {
        fileUri: selectedFile,
        password: sendPassword,
        connectionMode,
        connectIp: connectIp.trim() || null,
        relayAddr: relayAddr.trim() || null,
        remotePeerId: remotePeerId.trim() || null,
        port,
      });
    } catch (error) {
      console.error("Failed to send file:", error);
      setSnackbar({
        open: true,
        message: `Failed to send file: ${error}`,
        severity: "error",
      });
    }
  };

  const handleCancelSend = async () => {
    try {
      await invoke("cancel_send");
      setIsSending(false);
      setStatus("");
      setProgress(0);
      setSnackbar({
        open: true,
        message: "Transfer cancelled",
        severity: "success",
      });
    } catch (error) {
      console.error("Failed to cancel transfer:", error);
      setSnackbar({
        open: true,
        message: `Failed to cancel: ${error}`,
        severity: "error",
      });
    }
  };

  return (
    <Box sx={{ p: 2, pt: 3 }}>
      <Typography variant="h6">Send File</Typography>
      <Box sx={{ mb: 3 }}>
        <Box sx={{ display: "flex", gap: 1 }}>
          <TextField
            fullWidth
            label="File or Folder to Send"
            placeholder="Select file or folder"
            value={selectedFileName}
            slotProps={{
              input: {
                readOnly: true,
              },
            }}
            disabled={isSending}
            title={selectedFileName}
          />
          <IconButton
            color="primary"
            onClick={handleFileSelect}
            disabled={isSending}
            size="medium"
            title="Select file"
          >
            <FileIcon />
          </IconButton>
          <IconButton
            color="primary"
            onClick={handleFolderSelect}
            disabled={isSending}
            size="medium"
            title="Select folder"
          >
            <FolderIcon />
          </IconButton>
        </Box>
      </Box>

      <Box sx={{ mb: 3 }}>
        <Box sx={{ display: "flex", gap: 1 }}>
          <TextField
            fullWidth
            label="Password"
            placeholder="Enter or generate password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={isSending}
            type="text"
          />
          <IconButton
            onClick={handleGeneratePassword}
            color="primary"
            disabled={isSending}
            title="Generate password"
          >
            <RefreshIcon />
          </IconButton>
          {password && (
            <IconButton
              onClick={handleCopyPassword}
              color="primary"
              title="Copy password"
            >
              <CopyIcon />
            </IconButton>
          )}
        </Box>
      </Box>

      <Box sx={{ mb: 3 }}>
        <FormControl fullWidth disabled={isSending}>
          <InputLabel>Connection Mode</InputLabel>
          <Select
            value={connectionMode}
            label="Connection Mode"
            onChange={(e) =>
              setConnectionMode(e.target.value as ConnectionMode)
            }
          >
            <MenuItem value="listen">Listen</MenuItem>
            <MenuItem value="connect">Connect</MenuItem>
            <MenuItem value="relay_listen">Relay Listen</MenuItem>
            <MenuItem value="relay_dial">Relay Dial</MenuItem>
          </Select>
        </FormControl>
      </Box>

      {connectionMode === "connect" && (
        <Box sx={{ mb: 3 }}>
          <TextField
            fullWidth
            label="Target IP Address"
            placeholder="e.g., 192.168.1.100"
            value={connectIp}
            onChange={(e) => setConnectIp(e.target.value)}
            disabled={isSending}
          />
        </Box>
      )}

      {(connectionMode === "relay_listen" ||
        connectionMode === "relay_dial") && (
        <Box sx={{ mb: 3 }}>
          <TextField
            fullWidth
            label="Relay Address"
            placeholder="e.g., /ip4/1.2.3.4/tcp/4001/p2p/12D3K..."
            value={relayAddr}
            onChange={(e) => setRelayAddr(e.target.value)}
            disabled={isSending}
          />
        </Box>
      )}

      {connectionMode === "relay_dial" && (
        <Box sx={{ mb: 3 }}>
          <TextField
            fullWidth
            label="Remote Peer ID"
            placeholder="e.g., 12D3KooW..."
            value={remotePeerId}
            onChange={(e) => setRemotePeerId(e.target.value)}
            disabled={isSending}
          />
        </Box>
      )}

      {connectionMode === "relay_listen" && (
        <Box sx={{ mb: 3 }}>
          <Box sx={{ display: "flex", gap: 1 }}>
            <TextField
              fullWidth
              label="Your Peer ID"
              value={peerId}
              placeholder="Waiting for peer ID..."
              slotProps={{
                input: {
                  readOnly: true,
                },
              }}
              title={peerId}
            />
            <IconButton
              onClick={async () => {
                try {
                  await writeText(peerId);
                  setSnackbar({
                    open: true,
                    message: "Peer ID copied to clipboard",
                    severity: "success",
                  });
                } catch (error) {
                  console.error("Failed to copy peer ID:", error);
                  setSnackbar({
                    open: true,
                    message: "Failed to copy peer ID",
                    severity: "error",
                  });
                }
              }}
              color="primary"
              title="Copy Peer ID"
            >
              <CopyIcon />
            </IconButton>
          </Box>
        </Box>
      )}

      {status && (
        <Box sx={{ mb: 3 }}>
          <Typography variant="body2" color="primary" sx={{ mb: 1 }}>
            {status}
          </Typography>
          {isSending && (
            <LinearProgress variant="determinate" value={progress} />
          )}
        </Box>
      )}

      {!isSending ? (
        <Button
          fullWidth
          variant="contained"
          size="large"
          startIcon={<SendIcon />}
          onClick={handleSend}
        >
          START SENDING
        </Button>
      ) : (
        <Button
          fullWidth
          variant="contained"
          size="large"
          color="error"
          startIcon={<StopIcon />}
          onClick={handleCancelSend}
        >
          STOP
        </Button>
      )}

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

export default SendPage;

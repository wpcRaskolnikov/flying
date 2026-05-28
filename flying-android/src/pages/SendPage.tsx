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
import { useAtomValue } from "jotai";
import { portAtom } from "../store";
import { useSnackbar } from "../hooks";

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
  const { showSnackbar } = useSnackbar();

  const port = useAtomValue(portAtom);

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
      showSnackbar("File sent successfully", "success");
      setTimeout(() => {
        setStatus("");
        setProgress(0);
      }, 2000);
    });

    const unlisten3 = listen<string>("send-error", (event) => {
      setIsSending(false);
      setStatus("");
      setProgress(0);
      showSnackbar(event.payload, "error");
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
      showSnackbar("Failed to select file", "error");
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
      showSnackbar("Failed to select folder", "error");
    }
  };

  const handleCopyPassword = async () => {
    if (password) {
      await writeText(password);
      showSnackbar("Password copied to clipboard", "success");
    }
  };

  const handleGeneratePassword = async () => {
    try {
      const generatedPassword = await invoke<string>("generate_password");
      setPassword(generatedPassword);
      showSnackbar("Password generated", "success");
    } catch (error) {
      console.error("Failed to generate password:", error);
      showSnackbar("Failed to generate password", "error");
    }
  };

  const handleSend = async () => {
    if (!selectedFile) {
      showSnackbar("Please select a file", "error");
      return;
    }

    if (connectionMode === "connect" && !connectIp.trim()) {
      showSnackbar("Please enter target IP address", "error");
      return;
    }

    if (
      (connectionMode === "relay_listen" || connectionMode === "relay_dial") &&
      !relayAddr.trim()
    ) {
      showSnackbar("Please enter relay address", "error");
      return;
    }

    if (connectionMode === "relay_dial" && !remotePeerId.trim()) {
      showSnackbar("Please enter remote peer ID", "error");
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
        showSnackbar("Failed to generate password", "error");
        return;
      }
    }

    if (!sendPassword) {
      showSnackbar("Please enter or generate a password", "error");
      return;
    }

    try {
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
      showSnackbar(`Failed to send file: ${error}`, "error");
    }
  };

  const handleCancelSend = async () => {
    try {
      await invoke("cancel_send");
      setIsSending(false);
      setStatus("");
      setProgress(0);
      showSnackbar("Transfer cancelled", "success");
    } catch (error) {
      console.error("Failed to cancel transfer:", error);
      showSnackbar(`Failed to cancel: ${error}`, "error");
    }
  };

  return (
    <>
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
                  showSnackbar("Peer ID copied to clipboard", "success");
                } catch (error) {
                  console.error("Failed to copy peer ID:", error);
                  showSnackbar("Failed to copy peer ID", "error");
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
    </>
  );
}

export default SendPage;

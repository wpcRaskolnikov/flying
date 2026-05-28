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
  Download as DownloadIcon,
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

function ReceivePage() {
  const [password, setPassword] = useState("");
  const [connectionMode, setConnectionMode] =
    useState<ConnectionMode>("connect");
  const [connectIp, setConnectIp] = useState("");
  const [relayAddr, setRelayAddr] = useState("");
  const [remotePeerId, setRemotePeerId] = useState("");
  const [peerId, setPeerId] = useState("");
  const [isReceiving, setIsReceiving] = useState(false);
  const [status, setStatus] = useState("");
  const [progress, setProgress] = useState(0);
  const [outputDirUri, setOutputDirUri] = useState<string | null>(null);
  const [outputDirName, setOutputDirName] = useState<string | null>(null);
  const port = useAtomValue(portAtom);
  const { showSnackbar } = useSnackbar();

  useEffect(() => {
    const loadDefaultFolder = async () => {
      try {
        const folderPath = await invoke<string>("get_default_folder");
        setOutputDirName(folderPath);
        setOutputDirUri(folderPath);
      } catch (error) {
        console.error("Failed to load default folder:", error);
      }
    };
    loadDefaultFolder();

    const unlisten1 = listen("receive-start", () => {
      setIsReceiving(true);
      setStatus("Receiving file...");
      setProgress(0);
    });

    const unlisten2 = listen("receive-complete", () => {
      setIsReceiving(false);
      setStatus("Receive completed!");
      setProgress(100);
      showSnackbar("File received successfully", "success");
      setTimeout(() => {
        setStatus("");
        setProgress(0);
      }, 2000);
    });

    const unlisten3 = listen<string>("receive-error", (event) => {
      setIsReceiving(false);
      setStatus("");
      setProgress(0);
      showSnackbar(event.payload, "error");
    });

    const unlisten4 = listen<number>("receive-progress", (event) => {
      setProgress(event.payload);
      setStatus(`Receiving file... ${event.payload}%`);
    });

    const unlisten5 = listen<string>("receive-ready", (event) => {
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

  const handlePickFolder = async () => {
    try {
      const result = await invoke<[string, string] | null>("pick_folder");
      if (result) {
        const [uri, _name] = result;
        setOutputDirUri(uri);
        setOutputDirName(uri);
        showSnackbar(`Output folder set to: ${uri}`, "success");
      }
    } catch (error) {
      console.error("Failed to pick folder:", error);
      showSnackbar(`Failed to pick folder: ${error}`, "error");
    }
  };

  const handleReceive = async () => {
    if (!outputDirUri) {
      showSnackbar("Please select an output folder first", "error");
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

    let receivePassword = password.trim();

    if (
      (connectionMode === "listen" || connectionMode === "relay_listen") &&
      !receivePassword
    ) {
      try {
        receivePassword = await invoke<string>("generate_password");
        setPassword(receivePassword);
      } catch (error) {
        console.error("Failed to generate password:", error);
        showSnackbar("Failed to generate password", "error");
        return;
      }
    }

    if (!receivePassword) {
      showSnackbar("Please enter or generate a password", "error");
      return;
    }

    try {
      await invoke("receive_file", {
        password: receivePassword,
        connectionMode,
        connectIp: connectIp.trim() || null,
        relayAddr: relayAddr.trim() || null,
        remotePeerId: remotePeerId.trim() || null,
        outputDirUri: outputDirUri,
        port,
      });
    } catch (error) {
      console.error("Failed to receive file:", error);
      showSnackbar(`Failed to receive file: ${error}`, "error");
    }
  };

  const handleCancelReceive = async () => {
    try {
      await invoke("cancel_receive");
      setIsReceiving(false);
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
      <Typography variant="h6">Receive File</Typography>
      <Box sx={{ mb: 3 }}>
        <Box sx={{ display: "flex", gap: 1 }}>
          <TextField
            fullWidth
            label="Output Folder"
            placeholder="Select output folder"
            value={outputDirName || ""}
            slotProps={{
              input: {
                readOnly: true,
              },
            }}
            disabled={isReceiving}
            title={outputDirName || ""}
          />
          <IconButton
            color="primary"
            onClick={handlePickFolder}
            disabled={isReceiving}
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
            disabled={isReceiving}
            type="text"
          />
          <IconButton
            onClick={handleGeneratePassword}
            color="primary"
            disabled={isReceiving}
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
        <FormControl fullWidth disabled={isReceiving}>
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
            disabled={isReceiving}
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
            disabled={isReceiving}
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
            disabled={isReceiving}
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
          {isReceiving && (
            <LinearProgress variant="determinate" value={progress} />
          )}
        </Box>
      )}

      {!isReceiving ? (
        <Button
          fullWidth
          variant="contained"
          size="large"
          startIcon={<DownloadIcon />}
          onClick={handleReceive}
        >
          START RECEIVING
        </Button>
      ) : (
        <Button
          fullWidth
          variant="contained"
          size="large"
          color="error"
          startIcon={<StopIcon />}
          onClick={handleCancelReceive}
        >
          STOP
        </Button>
      )}
    </>
  );
}

export default ReceivePage;

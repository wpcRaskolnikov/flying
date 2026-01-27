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
  Alert as SnackbarAlert,
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
import { Store } from "@tauri-apps/plugin-store";
import { downloadDir } from "@tauri-apps/api/path";

type ConnectionMode = "listen" | "connect";

function ReceivePage() {
  const [password, setPassword] = useState("");
  const [connectionMode, setConnectionMode] =
    useState<ConnectionMode>("connect");
  const [connectIp, setConnectIp] = useState("");
  const [isReceiving, setIsReceiving] = useState(false);
  const [status, setStatus] = useState("");
  const [progress, setProgress] = useState(0);
  const [outputDirUri, setOutputDirUri] = useState<string | null>(null);
  const [outputDirName, setOutputDirName] = useState<string | null>(null);
  const [snackbar, setSnackbar] = useState({
    open: false,
    message: "",
    severity: "success" as "success" | "error",
  });

  useEffect(() => {
    // Load default folder from store
    const loadDefaultFolder = async () => {
      try {
        const store = await Store.load("settings.json");
        let folderPath = await store.get<string>("default_folder_path");

        // Initialize with Download folder if not set
        if (!folderPath) {
          folderPath = await downloadDir();

          // Save to store
          await store.set("default_folder_path", folderPath);
          await store.save();
        }

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
      setSnackbar({
        open: true,
        message: "File received successfully",
        severity: "success",
      });
      setTimeout(() => {
        setStatus("");
        setProgress(0);
      }, 2000);
    });

    const unlisten3 = listen<string>("receive-error", (event) => {
      setIsReceiving(false);
      setStatus("");
      setProgress(0);
      setSnackbar({ open: true, message: event.payload, severity: "error" });
    });

    const unlisten4 = listen<number>("receive-progress", (event) => {
      setProgress(event.payload);
      setStatus(`Receiving file... ${event.payload}%`);
    });

    return () => {
      unlisten1.then((fn) => fn());
      unlisten2.then((fn) => fn());
      unlisten3.then((fn) => fn());
      unlisten4.then((fn) => fn());
    };
  }, []);

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

  const handlePickFolder = async () => {
    try {
      const result = await invoke<[string, string] | null>("pick_folder");
      if (result) {
        const [uri, _name] = result;
        setOutputDirUri(uri);
        setOutputDirName(uri);
        setSnackbar({
          open: true,
          message: `Output folder set to: ${uri}`,
          severity: "success",
        });
      }
    } catch (error) {
      console.error("Failed to pick folder:", error);
      setSnackbar({
        open: true,
        message: `Failed to pick folder: ${error}`,
        severity: "error",
      });
    }
  };

  const handleReceive = async () => {
    if (!outputDirUri) {
      setSnackbar({
        open: true,
        message: "Please select an output folder first",
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

    let receivePassword = password.trim();

    if (connectionMode === "listen" && !receivePassword) {
      try {
        receivePassword = await invoke<string>("generate_password");
        setPassword(receivePassword);
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

    if (!receivePassword) {
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
      await invoke("receive_file", {
        password: receivePassword,
        connectionMode,
        connectIp: connectIp.trim() || null,
        outputDirUri: outputDirUri,
        port,
      });
    } catch (error) {
      console.error("Failed to receive file:", error);
      setSnackbar({
        open: true,
        message: `Failed to receive file: ${error}`,
        severity: "error",
      });
    }
  };

  const handleCancelReceive = async () => {
    try {
      await invoke("cancel_receive");
      setIsReceiving(false);
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
      <Typography variant="h6">Receive File</Typography>
      <Box sx={{ mb: 3 }}>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          Output Folder
        </Typography>
        <Box sx={{ display: "flex", gap: 1 }}>
          <TextField
            fullWidth
            placeholder="Select output folder"
            value={outputDirName || ""}
            slotProps={{
              input: {
                readOnly: true,
              },
            }}
            disabled={isReceiving}
            size="small"
            title={outputDirName || ""}
          />
          <Button
            variant="contained"
            startIcon={<FolderIcon />}
            onClick={handlePickFolder}
            disabled={isReceiving}
            size="small"
            sx={{ whiteSpace: "nowrap", minWidth: "auto", px: 2 }}
          >
            SELECT
          </Button>
        </Box>
      </Box>

      <Box sx={{ mb: 3 }}>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          Password
        </Typography>
        <Box sx={{ display: "flex", gap: 1 }}>
          <TextField
            fullWidth
            placeholder="Enter or generate password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={isReceiving}
            type="text"
            size="small"
          />
          <IconButton
            onClick={handleGeneratePassword}
            color="primary"
            size="small"
            disabled={isReceiving}
            title="Generate password"
          >
            <RefreshIcon />
          </IconButton>
          {password && (
            <IconButton
              onClick={handleCopyPassword}
              color="primary"
              size="small"
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
      <SnackbarAlert severity="info" sx={{ mt: 3 }}>
        Android: Files will be saved to Download folder
      </SnackbarAlert>

      <Snackbar
        open={snackbar.open}
        autoHideDuration={3000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
        anchorOrigin={{ vertical: "bottom", horizontal: "center" }}
        sx={{ bottom: 72 }}
      >
        <SnackbarAlert severity={snackbar.severity} sx={{ width: "100%" }}>
          {snackbar.message}
        </SnackbarAlert>
      </Snackbar>
    </Box>
  );
}

export default ReceivePage;

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
} from "@mui/icons-material";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";

type ConnectionMode = "listen" | "connect";

function ReceivePage() {
  const [password, setPassword] = useState("");
  const [connectionMode, setConnectionMode] =
    useState<ConnectionMode>("connect");
  const [connectIp, setConnectIp] = useState("");
  const [isReceiving, setIsReceiving] = useState(false);
  const [status, setStatus] = useState("");
  const [outputDirUri, setOutputDirUri] = useState<string | null>(null);
  const [outputDirName, setOutputDirName] = useState<string | null>(null);
  const [snackbar, setSnackbar] = useState({
    open: false,
    message: "",
    severity: "success" as "success" | "error",
  });

  useEffect(() => {
    const unlisten1 = listen("receive-start", () => {
      setIsReceiving(true);
      setStatus("Receiving file...");
    });

    const unlisten2 = listen("receive-complete", () => {
      setIsReceiving(false);
      setStatus("Receive completed!");
      setSnackbar({
        open: true,
        message: "File received successfully",
        severity: "success",
      });
      setTimeout(() => setStatus(""), 2000);
    });

    const unlisten3 = listen<string>("receive-error", (event) => {
      setIsReceiving(false);
      setStatus("");
      setSnackbar({ open: true, message: event.payload, severity: "error" });
    });

    return () => {
      unlisten1.then((fn) => fn());
      unlisten2.then((fn) => fn());
      unlisten3.then((fn) => fn());
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

  const handleRegeneratePassword = async () => {
    if (password) {
      try {
        const newPassword = await invoke<string>("generate_password");
        setPassword(newPassword);
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
  };

  const handlePickFolder = async () => {
    try {
      const result = await invoke<[string, string] | null>("pick_folder");
      if (result) {
        const [uri, name] = result;
        setOutputDirUri(uri);
        setOutputDirName(name);
        setSnackbar({
          open: true,
          message: `Output folder set to: ${name}`,
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
    if (!receivePassword && connectionMode === "listen") {
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
    } else if (!receivePassword) {
      setSnackbar({
        open: true,
        message: "Please enter a password",
        severity: "error",
      });
      return;
    }

    try {
      await invoke("receive_file", {
        password: receivePassword,
        connectionMode,
        connectIp: connectIp.trim() || null,
        outputDirUri: outputDirUri,
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

  return (
    <Box sx={{ p: 2, pt: 3 }}>
      <SnackbarAlert severity="info" sx={{ mb: 3 }}>
        Android: Files will be saved to Download folder, please select any
        folder below to continue
      </SnackbarAlert>

      <Box sx={{ mb: 3 }}>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          Output Folder
        </Typography>
        <Box sx={{ display: "flex", gap: 1 }}>
          <TextField
            fullWidth
            placeholder="Select output folder"
            value={outputDirName || ""}
            slotProps={{ input: { readOnly: true } }}
            disabled={isReceiving}
            size="small"
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
          Password{" "}
          {connectionMode === "listen" ? "(Auto-generated on receive)" : ""}
        </Typography>
        <Box sx={{ display: "flex", gap: 1 }}>
          <TextField
            fullWidth
            placeholder={
              connectionMode === "listen"
                ? "Will be generated"
                : "Enter password"
            }
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={isReceiving || connectionMode === "listen"}
            type="text"
            size="small"
          />
          {connectionMode === "listen" && password && (
            <IconButton
              onClick={handleCopyPassword}
              color="primary"
              size="small"
            >
              <CopyIcon />
            </IconButton>
          )}
          {connectionMode === "listen" && password && (
            <Button
              variant="contained"
              startIcon={<RefreshIcon />}
              onClick={handleRegeneratePassword}
              disabled={isSending}
              size="small"
              sx={{ whiteSpace: "nowrap", minWidth: "auto", px: 2 }}
            >
              Regenerate
            </Button>
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
          {isReceiving && <LinearProgress />}
        </Box>
      )}

      <Button
        fullWidth
        variant="contained"
        size="large"
        startIcon={<DownloadIcon />}
        onClick={handleReceive}
        disabled={isReceiving}
      >
        START RECEIVING
      </Button>

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

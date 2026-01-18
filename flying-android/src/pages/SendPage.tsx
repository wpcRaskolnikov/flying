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
} from "@mui/icons-material";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";

type ConnectionMode = "listen" | "connect";

function SendPage() {
  const [selectedFile, setSelectedFile] = useState<string>("");
  const [selectedFileName, setSelectedFileName] = useState<string>("");
  const [password, setPassword] = useState("");
  const [connectionMode, setConnectionMode] =
    useState<ConnectionMode>("listen");
  const [connectIp, setConnectIp] = useState("");
  const [isSending, setIsSending] = useState(false);
  const [status, setStatus] = useState("");
  const [snackbar, setSnackbar] = useState({
    open: false,
    message: "",
    severity: "success" as "success" | "error",
  });

  useEffect(() => {
    const unlisten1 = listen("send-start", () => {
      setIsSending(true);
      setStatus("Sending file...");
    });

    const unlisten2 = listen("send-complete", () => {
      setIsSending(false);
      setStatus("Send completed!");
      setSnackbar({
        open: true,
        message: "File sent successfully",
        severity: "success",
      });
      setTimeout(() => setStatus(""), 2000);
    });

    const unlisten3 = listen<string>("send-error", (event) => {
      setIsSending(false);
      setStatus("");
      setSnackbar({ open: true, message: event.payload, severity: "error" });
    });

    return () => {
      unlisten1.then((fn) => fn());
      unlisten2.then((fn) => fn());
      unlisten3.then((fn) => fn());
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

    // Generate password for listen mode when sending
    let sendPassword = password.trim();
    if (connectionMode === "listen") {
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
    } else if (!sendPassword) {
      setSnackbar({
        open: true,
        message: "Please enter a password",
        severity: "error",
      });
      return;
    }

    try {
      await invoke("send_file_from_uri", {
        fileUri: selectedFile,
        password: sendPassword,
        connectionMode,
        connectIp: connectIp.trim() || null,
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

  return (
    <Box sx={{ p: 2, pt: 3 }}>
      <Box sx={{ mb: 3 }}>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          File to Send
        </Typography>
        <Box sx={{ display: "flex", gap: 1 }}>
          <TextField
            fullWidth
            placeholder="Select file"
            value={selectedFileName}
            slotProps={{ input: { readOnly: true } }}
            disabled={isSending}
            size="small"
          />
          <Button
            variant="contained"
            startIcon={<FileIcon />}
            onClick={handleFileSelect}
            disabled={isSending}
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
          {connectionMode === "listen" ? "(Auto-generated on send)" : ""}
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
            disabled={isSending || connectionMode === "listen"}
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

      {status && (
        <Box sx={{ mb: 3 }}>
          <Typography variant="body2" color="primary" sx={{ mb: 1 }}>
            {status}
          </Typography>
          {isSending && <LinearProgress />}
        </Box>
      )}

      <Button
        fullWidth
        variant="contained"
        size="large"
        startIcon={<SendIcon />}
        onClick={handleSend}
        disabled={isSending}
      >
        START SENDING
      </Button>

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

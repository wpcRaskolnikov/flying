import { useState, useEffect, useRef } from "react";
import {
  Box,
  Button,
  Stack,
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
  Autorenew as AutorenewIcon,
  Stop as StopIcon,
} from "@mui/icons-material";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { useAtomValue } from "jotai";
import { portAtom } from "../store";
import { useSnackbar } from "../hooks";
import type { ConnectionConfig, TransferStatusPayload, PickedEntity } from "../types";

function SendPage() {
  const [selectedFile, setSelectedFile] = useState<string>("");
  const [selectedFileName, setSelectedFileName] = useState<string>("");
  const [password, setPassword] = useState("");
  const [config, setConfig] = useState<ConnectionConfig>({
    mode: "connect",
    connectIp: "",
  });
  const [isSending, setIsSending] = useState(false);
  const [status, setStatus] = useState("");
  const [progress, setProgress] = useState(0);

  const { showSnackbar } = useSnackbar();
  const port = useAtomValue(portAtom);

  const configModeRef = useRef(config.mode);
  configModeRef.current = config.mode;
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const unlisten = listen<TransferStatusPayload>(
      "send-status-update",
      (event) => {
        const { status, progress, message, peerId } = event.payload;

        switch (status) {
          case "Ready":
            if (peerId && configModeRef.current === "relay_listen") {
              setConfig((prev) => ({ ...prev, peerId }));
            }
            setIsSending(true);
            setStatus("Waiting for connection...");
            break;
          case "Sending":
            setIsSending(true);
            setProgress(progress);
            setStatus(`Sending file... ${progress}%`);
            break;
          case "Completed":
            setIsSending(false);
            setStatus("Send completed!");
            setProgress(100);
            showSnackbar("File sent successfully", "success");

            if (timerRef.current) clearTimeout(timerRef.current);
            timerRef.current = setTimeout(() => {
              setStatus("");
              setProgress(0);
            }, 2000);
            break;
          case "Error":
            setIsSending(false);
            setStatus("");
            setProgress(0);
            showSnackbar(message || "An error occurred", "error");
            break;
        }
      },
    );

    return () => {
      unlisten.then((fn) => fn());
    };
  }, [showSnackbar]);

  const handleFileSelect = async () => {
    try {
      const result = await invoke<PickedEntity | null>("pick_file");
      if (result) {
        setSelectedFile(result.pathOrUri);
        setSelectedFileName(result.name);
      }
    } catch (error) {
      console.error("Failed to select file:", error);
      showSnackbar("Failed to select file", "error");
    }
  };

  const handleFolderSelect = async () => {
    try {
      const result = await invoke<PickedEntity | null>("pick_folder");
      if (result) {
        setSelectedFile(result.pathOrUri);
        setSelectedFileName(result.name);
      }
    } catch (error) {
      console.error("Failed to select folder:", error);
      showSnackbar("Failed to select folder", "error");
    }
  };

  const generatePassword = async (): Promise<string> => {
    try {
      const generatedPassword = await invoke<string>("generate_password");
      setPassword(generatedPassword);
      showSnackbar("Password generated", "success");
      return generatedPassword;
    } catch (error) {
      console.error("Failed to generate password:", error);
      showSnackbar("Failed to generate password", "error");
      return "";
    }
  };

  const handleCopyPassword = async () => {
    if (password) {
      await writeText(password);
      showSnackbar("Password copied to clipboard", "success");
    }
  };

  const handleSend = async () => {
    if (!selectedFile) {
      showSnackbar("Please select a file", "error");
      return;
    }

    if (config.mode === "connect" && !config.connectIp.trim()) {
      showSnackbar("Please enter target IP address", "error");
      return;
    }

    if (
      (config.mode === "relay_listen" || config.mode === "relay_dial") &&
      !config.relayAddr.trim()
    ) {
      showSnackbar("Please enter relay address", "error");
      return;
    }

    if (config.mode === "relay_dial" && !config.remotePeerId.trim()) {
      showSnackbar("Please enter remote peer ID", "error");
      return;
    }

    let sendPassword = password.trim();

    if (
      (config.mode === "listen" || config.mode === "relay_listen") &&
      !sendPassword
    ) {
      sendPassword = await generatePassword();
    }
    if (!sendPassword) {
      showSnackbar("Please enter or generate a password", "error");
      return;
    }

    try {
      setIsSending(true);
      await invoke("send_file", {
        fileUri: selectedFile,
        password: sendPassword,
        config,
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
    <Stack spacing={2}>
      <Typography variant="h6">Send File</Typography>

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
          onClick={generatePassword}
          color="primary"
          disabled={isSending}
          title="Generate password"
        >
          <AutorenewIcon />
        </IconButton>
        <IconButton
          onClick={handleCopyPassword}
          color="primary"
          title="Copy password"
        >
          <CopyIcon />
        </IconButton>
      </Box>

      <FormControl fullWidth disabled={isSending}>
        <InputLabel>Connection Mode</InputLabel>
        <Select
          value={config.mode}
          label="Connection Mode"
          onChange={(e) => {
            const mode = e.target.value;
            switch (mode) {
              case "connect":
                setConfig({ mode, connectIp: "" });
                break;
              case "listen":
                setConfig({ mode });
                break;
              case "relay_listen":
                setConfig({ mode, relayAddr: "", peerId: "" });
                break;
              case "relay_dial":
                setConfig({ mode, relayAddr: "", remotePeerId: "" });
                break;
            }
          }}
        >
          <MenuItem value="listen">Listen</MenuItem>
          <MenuItem value="connect">Connect</MenuItem>
          <MenuItem value="relay_listen">Relay Listen</MenuItem>
          <MenuItem value="relay_dial">Relay Dial</MenuItem>
        </Select>
      </FormControl>

      {config.mode === "connect" && (
        <TextField
          fullWidth
          label="Target IP Address"
          placeholder="e.g., 192.168.1.100"
          value={config.connectIp}
          onChange={(e) =>
            setConfig((prev) => ({ ...prev, connectIp: e.target.value }))
          }
          disabled={isSending}
        />
      )}

      {(config.mode === "relay_listen" || config.mode === "relay_dial") && (
        <TextField
          fullWidth
          label="Relay Address"
          placeholder="e.g., /ip4/1.2.3.4/tcp/4001/p2p/12D3K..."
          value={config.relayAddr}
          onChange={(e) =>
            setConfig((prev) => ({ ...prev, relayAddr: e.target.value }))
          }
          disabled={isSending}
        />
      )}

      {config.mode === "relay_dial" && (
        <TextField
          fullWidth
          label="Remote Peer ID"
          placeholder="e.g., 12D3KooW..."
          value={config.remotePeerId}
          onChange={(e) =>
            setConfig((prev) => ({ ...prev, remotePeerId: e.target.value }))
          }
          disabled={isSending}
        />
      )}

      {config.mode === "relay_listen" && (
        <Box sx={{ display: "flex", gap: 1 }}>
          <TextField
            fullWidth
            label="Your Peer ID"
            value={config.peerId}
            placeholder="Waiting for peer ID..."
            slotProps={{
              input: {
                readOnly: true,
              },
            }}
            title={config.peerId}
          />
          <IconButton
            onClick={async () => {
              try {
                await writeText(config.peerId);
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
      )}

      {status && (
        <Box>
          <Typography variant="body2" color="primary" sx={{ mb: 1 }}>
            {status}
          </Typography>
          {progress > 0 && (
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
    </Stack>
  );
}

export default SendPage;

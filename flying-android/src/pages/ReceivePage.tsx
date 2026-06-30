import { useState, useEffect, useRef } from "react";
import {
  Box,
  Button,
  Stack,
  TextField,
  Autocomplete,
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
  Autorenew as AutorenewIcon,
  Stop as StopIcon,
  Delete as DeleteIcon,
} from "@mui/icons-material";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { useAtomValue } from "jotai";
import { portAtom } from "../store";
import { useSnackbar, useInputHistory } from "../hooks";
import type { ConnectionConfig, TransferStatusPayload, PickedEntity } from "../types";

function ReceivePage() {
  const [outputDirUri, setOutputDirUri] = useState<string>("");
  const [outputDirName, setOutputDirName] = useState<string>("");
  const [password, setPassword] = useState("");
  const [config, setConfig] = useState<ConnectionConfig>({
    mode: "connect",
    connectIp: "",
  });
  const [isReceiving, setIsReceiving] = useState(false);
  const [status, setStatus] = useState("");
  const [progress, setProgress] = useState(0);

  const port = useAtomValue(portAtom);
  const { showSnackbar } = useSnackbar();
  const connectIpHistory = useInputHistory("receive-connectIp");
  const relayAddrHistory = useInputHistory("receive-relayAddr");

  const configModeRef = useRef(config.mode);
  configModeRef.current = config.mode;
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const loadDefaultFolder = async () => {
    try {
      const folderPath = await invoke<string>("get_default_folder");
      setOutputDirName(folderPath);
      setOutputDirUri(folderPath);
    } catch (error) {
      console.error("Failed to load default folder:", error);
    }
  };

  useEffect(() => {
    loadDefaultFolder();

    const unlisten = listen<TransferStatusPayload>(
      "receive-status-update",
      (event) => {
        const { status, progress, message, peerId } = event.payload;

        switch (status) {
          case "Ready":
            if (peerId && configModeRef.current === "relay_listen") {
              setConfig((prev) => ({ ...prev, peerId }));
            }
            setIsReceiving(true);
            setStatus("Waiting for connection...");
            break;
          case "Sending":
            setIsReceiving(true);
            setProgress(progress);
            setStatus(`Receiving file... ${progress}%`);
            break;
          case "Completed":
            setIsReceiving(false);
            setStatus("Receive completed!");
            setProgress(100);
            showSnackbar("File received successfully", "success");

            if (timerRef.current) clearTimeout(timerRef.current);
            timerRef.current = setTimeout(() => {
              setStatus("");
              setProgress(0);
            }, 2000);
            break;
          case "Error":
            setIsReceiving(false);
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

  const handlePickFolder = async () => {
    try {
      const result = await invoke<PickedEntity | null>("pick_folder");
      if (result) {
        setOutputDirUri(result.pathOrUri);
        setOutputDirName(result.name);
      }
    } catch (error) {
      console.error("Failed to pick folder:", error);
      showSnackbar(`Failed to pick folder: ${error}`, "error");
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

  const handleReceive = async () => {
    if (!outputDirUri) {
      showSnackbar("Please select an output folder first", "error");
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

    let receivePassword = password.trim();

    if (
      (config.mode === "listen" || config.mode === "relay_listen") &&
      !receivePassword
    ) {
      receivePassword = await generatePassword();
    }
    if (!receivePassword) {
      showSnackbar("Please enter or generate a password", "error");
      return;
    }

    try {
      // Save to history
      if (config.mode === "connect") {
        connectIpHistory.addToHistory(config.connectIp);
      } else if (config.mode === "relay_listen" || config.mode === "relay_dial") {
        relayAddrHistory.addToHistory(config.relayAddr);
      }

      setIsReceiving(true);
      await invoke("receive_file", {
        password: receivePassword,
        config,
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
    <Stack spacing={2}>
      <Typography variant="h6">Receive File</Typography>

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
          onClick={generatePassword}
          color="primary"
          disabled={isReceiving}
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

      <FormControl fullWidth disabled={isReceiving}>
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
        <Autocomplete
          freeSolo
          options={connectIpHistory.history}
          value={config.connectIp}
          onInputChange={(_, newValue) =>
            setConfig((prev) => ({ ...prev, connectIp: newValue }))
          }
          disabled={isReceiving}
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
                  connectIpHistory.removeFromHistory(option);
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
              label="Target IP Address"
              placeholder="e.g., 192.168.1.100"
            />
          )}
        />
      )}

      {(config.mode === "relay_listen" || config.mode === "relay_dial") && (
        <Autocomplete
          freeSolo
          options={relayAddrHistory.history}
          value={config.relayAddr}
          onInputChange={(_, newValue) =>
            setConfig((prev) => ({ ...prev, relayAddr: newValue }))
          }
          disabled={isReceiving}
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
                  relayAddrHistory.removeFromHistory(option);
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
              label="Relay Address"
              placeholder="e.g., /ip4/1.2.3.4/tcp/4001/p2p/12D3K..."
            />
          )}
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
          disabled={isReceiving}
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
    </Stack>
  );
}

export default ReceivePage;

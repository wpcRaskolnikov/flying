import { useState, useEffect } from "react";
import {
  Box,
  TextField,
  Typography,
  Alert,
  IconButton,
} from "@mui/material";
import { Folder as FolderIcon } from "@mui/icons-material";
import { invoke } from "@tauri-apps/api/core";
import { getVersion } from "@tauri-apps/api/app";
import { useAtom } from "jotai";
import { portAtom } from "../store";
import { useSnackbar } from "../hooks";

function SettingsPage() {
  const [defaultFolder, setDefaultFolder] = useState<string>("");
  const [port, setPort] = useAtom(portAtom);
  const [version, setVersion] = useState<string>("");
  const { showSnackbar } = useSnackbar();

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    try {
      const folderPath = await invoke<string>("get_default_folder");
      setDefaultFolder(folderPath);
      const versionStr = await getVersion();
      setVersion(versionStr);
    } catch (error) {
      console.error("Failed to load settings:", error);
    }
  };

  const handleSelectFolder = async () => {
    try {
      const result = await invoke<[string, string] | null>("pick_folder");
      if (result) {
        const [uri, _name] = result;
        setDefaultFolder(uri);
        showSnackbar("Default folder updated", "success");
      }
    } catch (error) {
      console.error("Failed to select folder:", error);
      showSnackbar(`Failed to select folder: ${error}`, "error");
    }
  };

  return (
    <>
      <Typography variant="h6">Settings</Typography>

      <Box sx={{ mb: 3 }}>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          Default Receive Folder
        </Typography>
        <Box sx={{ display: "flex", gap: 1 }}>
          <TextField
            fullWidth
            placeholder="Select default folder"
            value={defaultFolder}
            slotProps={{
              input: {
                readOnly: true,
              },
            }}
            size="small"
            title={defaultFolder}
          />
          <IconButton
            color="primary"
            onClick={handleSelectFolder}
            size="medium"
            title="Select folder"
          >
            <FolderIcon />
          </IconButton>
        </Box>
      </Box>

      <Box sx={{ mb: 3 }}>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          Port Configuration
        </Typography>
        <TextField
          fullWidth
          placeholder="Port number (1-65535)"
          value={port}
          onChange={(e) => setPort(Number(e.target.value))}
          size="small"
          type="number"
          slotProps={{
            input: {
              inputProps: { min: 1, max: 65535 },
            },
          }}
        />
      </Box>

      <Alert severity="info" sx={{ mt: 2 }}>
        Android: Files will be saved to the Download folder. The folder
        selection above is used as a reference but actual files go to Download.
      </Alert>

      <Box
        sx={{
          mt: 4,
          textAlign: "center",
          color: "text.secondary",
        }}
      >
        <Typography variant="caption" display="block">
          Flying v{version}
        </Typography>
      </Box>
    </>
  );
}

export default SettingsPage;

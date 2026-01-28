import { useState, useEffect } from "react";
import {
  Box,
  TextField,
  Typography,
  Snackbar,
  Alert,
  IconButton,
} from "@mui/material";
import { Folder as FolderIcon, Save as SaveIcon } from "@mui/icons-material";
import { invoke } from "@tauri-apps/api/core";
import { Store } from "@tauri-apps/plugin-store";

function SettingsPage() {
  const [defaultFolder, setDefaultFolder] = useState<string>("");
  const [port, setPort] = useState<number>(3290);
  const [snackbar, setSnackbar] = useState({
    open: false,
    message: "",
    severity: "success" as "success" | "error",
  });

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    try {
      const folderPath = await invoke<string>("get_default_folder");
      setDefaultFolder(folderPath);

      // Load port from store
      const storeInstance = await Store.load("settings.json");
      const savedPort = await storeInstance.get<number>("port");
      if (savedPort) {
        setPort(savedPort);
      }
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

        // Reload store to ensure valid resource
        const storeInstance = await Store.load("settings.json");
        await storeInstance.set("default_folder_path", uri);
        await storeInstance.save();

        setSnackbar({
          open: true,
          message: "Default folder updated",
          severity: "success",
        });
      }
    } catch (error) {
      console.error("Failed to select folder:", error);
      setSnackbar({
        open: true,
        message: `Failed to select folder: ${error}`,
        severity: "error",
      });
    }
  };

  const handleSavePort = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    try {
      if (isNaN(port) || port < 1 || port > 65535) {
        setSnackbar({
          open: true,
          message: "Port must be between 1 and 65535",
          severity: "error",
        });
        return;
      }

      // Reload store to ensure valid resource
      const storeInstance = await Store.load("settings.json");
      await storeInstance.set("port", port);
      await storeInstance.save();

      setSnackbar({
        open: true,
        message: "Port saved. Changes will take effect on next transfer",
        severity: "success",
      });
    } catch (error) {
      console.error("Failed to save port:", error);
      setSnackbar({
        open: true,
        message: `Failed to save port: ${error}`,
        severity: "error",
      });
    }
  };

  return (
    <Box sx={{ p: 2, pt: 3 }}>
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
        <Box
          component="form"
          onSubmit={handleSavePort}
          sx={{ display: "flex", gap: 1 }}
        >
          <TextField
            name="port"
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
          <IconButton
            type="submit"
            color="primary"
            size="medium"
            title="Save port"
          >
            <SaveIcon />
          </IconButton>
        </Box>
      </Box>

      <Alert severity="info" sx={{ mt: 2 }}>
        Android: Files will be saved to the Download folder. The folder
        selection above is used as a reference but actual files go to Download.
      </Alert>

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

export default SettingsPage;

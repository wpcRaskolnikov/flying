import { useState, useEffect } from "react";
import {
  Box,
  Button,
  TextField,
  Typography,
  Snackbar,
  Alert,
  Paper,
} from "@mui/material";
import { Folder as FolderIcon } from "@mui/icons-material";
import { invoke } from "@tauri-apps/api/core";
import { Store } from "@tauri-apps/plugin-store";
import { downloadDir } from "@tauri-apps/api/path";

function SettingsPage() {
  const [defaultFolder, setDefaultFolder] = useState<string>("");
  const [store, setStore] = useState<Store | null>(null);
  const [snackbar, setSnackbar] = useState({
    open: false,
    message: "",
    severity: "success" as "success" | "error",
  });

  useEffect(() => {
    const initStore = async () => {
      const storeInstance = await Store.load("settings.json");
      setStore(storeInstance);
      await loadSettings(storeInstance);
    };
    initStore();
  }, []);

  const loadSettings = async (storeInstance: Store) => {
    try {
      let folderPath = await storeInstance.get<string>("default_folder_path");

      // Initialize with Download folder if not set
      if (!folderPath) {
        folderPath = await downloadDir();

        // Save to store
        await storeInstance.set("default_folder_path", folderPath);
        await storeInstance.save();
      }

      setDefaultFolder(folderPath);
    } catch (error) {
      console.error("Failed to load settings:", error);
    }
  };

  const handleSelectFolder = async () => {
    if (!store) return;

    try {
      const result = await invoke<[string, string] | null>("pick_folder");
      if (result) {
        const [uri, _name] = result;
        setDefaultFolder(uri);

        await store.set("default_folder_path", uri);
        await store.save();

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
    if (!store) return;

    const formData = new FormData(event.currentTarget);
    const portValue = formData.get("port") as string;

    try {
      const portNumber = parseInt(portValue, 10);
      if (isNaN(portNumber) || portNumber < 1 || portNumber > 65535) {
        setSnackbar({
          open: true,
          message: "Port must be between 1 and 65535",
          severity: "error",
        });
        return;
      }

      await store.set("port", portNumber);
      await store.save();

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
      <Paper sx={{ p: 2, mb: 2 }}>
        <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 500 }}>
          Default Receive Folder
        </Typography>

        <Box sx={{ display: "flex", gap: 1, alignItems: "center" }}>
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
          <Button
            variant="contained"
            startIcon={<FolderIcon />}
            onClick={handleSelectFolder}
            size="small"
            sx={{ whiteSpace: "nowrap", minWidth: "auto", px: 2 }}
          >
            SELECT
          </Button>
        </Box>
      </Paper>

      <Paper sx={{ p: 2, mb: 2 }}>
        <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 500 }}>
          Port Configuration
        </Typography>

        <Box
          component="form"
          onSubmit={handleSavePort}
          sx={{ display: "flex", gap: 1, alignItems: "center" }}
        >
          <TextField
            name="port"
            fullWidth
            placeholder="Port number (1-65535)"
            defaultValue="3290"
            size="small"
            type="number"
            slotProps={{
              input: {
                inputProps: { min: 1, max: 65535 },
              },
            }}
          />
          <Button
            type="submit"
            variant="contained"
            size="small"
            sx={{ whiteSpace: "nowrap", minWidth: "auto", px: 2 }}
          >
            SAVE
          </Button>
        </Box>
      </Paper>

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

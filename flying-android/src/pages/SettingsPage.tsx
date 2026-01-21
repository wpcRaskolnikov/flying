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

function SettingsPage() {
  const [defaultFolder, setDefaultFolder] = useState<string>("");
  const [defaultFolderName, setDefaultFolderName] = useState<string>("");
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
      const settings = await invoke<{
        folder_uri: string;
        folder_name: string;
      }>("get_default_receive_folder");
      setDefaultFolder(settings.folder_uri);
      setDefaultFolderName(settings.folder_name);
    } catch (error) {
      console.error("Failed to load settings:", error);
    }
  };

  const handleSelectFolder = async () => {
    try {
      const result = await invoke<[string, string] | null>("pick_folder");
      if (result) {
        const [uri, name] = result;
        setDefaultFolder(uri);
        setDefaultFolderName(name);

        // Save to settings
        await invoke("set_default_receive_folder", {
          folderUri: uri,
          folderName: name,
        });

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

  return (
    <Box sx={{ p: 2, pt: 3 }}>
      <Typography variant="h5" gutterBottom sx={{ fontWeight: 600, mb: 3 }}>
        Settings
      </Typography>

      <Paper sx={{ p: 2, mb: 2 }}>
        <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 500 }}>
          Default Receive Folder
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Files will be saved to this folder by default when receiving
        </Typography>

        <Box sx={{ display: "flex", gap: 1, alignItems: "center" }}>
          <TextField
            fullWidth
            placeholder="Select default folder"
            value={defaultFolderName}
            slotProps={{ input: { readOnly: true } }}
            size="small"
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

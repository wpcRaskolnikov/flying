import { useState } from "react";
import {
  Box,
  Button,
  List,
  ListItem,
  ListItemText,
  IconButton,
  Typography,
  CircularProgress,
  Alert,
  Snackbar,
} from "@mui/material";
import {
  Refresh as RefreshIcon,
  ContentCopy as CopyIcon,
} from "@mui/icons-material";
import { invoke } from "@tauri-apps/api/core";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";

interface DiscoveredHost {
  name: string;
  ip: string;
}

function DiscoverPage() {
  const [hosts, setHosts] = useState<DiscoveredHost[]>([]);
  const [isDiscovering, setIsDiscovering] = useState(false);
  const [snackbar, setSnackbar] = useState({ open: false, message: "" });

  const handleDiscover = async () => {
    setIsDiscovering(true);
    setHosts([]);

    try {
      const discovered = await invoke<DiscoveredHost[]>("discover_hosts");
      setHosts(discovered);

      if (discovered.length === 0) {
        setSnackbar({ open: true, message: "No hosts found" });
      } else {
        setSnackbar({
          open: true,
          message: `Found ${discovered.length} host(s)`,
        });
      }
    } catch (error) {
      console.error("Failed to discover hosts:", error);
      setSnackbar({ open: true, message: `Discovery failed: ${error}` });
    } finally {
      setIsDiscovering(false);
    }
  };

  const handleCopyIp = async (ip: string) => {
    await writeText(ip);
    setSnackbar({ open: true, message: `IP ${ip} copied to clipboard` });
  };

  return (
    <Box sx={{ p: 2, pt: 3 }}>
      <Box
        sx={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          mb: 3,
        }}
      >
        <Typography variant="h6">Discover Hosts</Typography>
        <Button
          variant="contained"
          startIcon={
            isDiscovering ? (
              <CircularProgress size={20} color="inherit" />
            ) : (
              <RefreshIcon />
            )
          }
          onClick={handleDiscover}
          disabled={isDiscovering}
        >
          {isDiscovering ? "Discovering..." : "Discover"}
        </Button>
      </Box>

      {hosts.length === 0 && !isDiscovering && (
        <Alert severity="info" sx={{ mb: 2 }}>
          Click "Discover" to find hosts on your local network
        </Alert>
      )}

      {hosts.length > 0 && (
        <List>
          {hosts.map((host, index) => (
            <ListItem
              key={index}
              sx={{
                bgcolor: "background.paper",
                mb: 1,
                borderRadius: 1,
                border: "1px solid",
                borderColor: "divider",
              }}
              secondaryAction={
                <IconButton
                  edge="end"
                  onClick={() => handleCopyIp(host.ip)}
                  color="primary"
                >
                  <CopyIcon />
                </IconButton>
              }
            >
              <ListItemText
                primary={host.name || "Unknown Host"}
                secondary={host.ip}
                slotProps={{
                  primary: { fontWeight: "medium" },
                }}
              />
            </ListItem>
          ))}
        </List>
      )}

      <Snackbar
        open={snackbar.open}
        autoHideDuration={2000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
        message={snackbar.message}
        anchorOrigin={{ vertical: "bottom", horizontal: "center" }}
        sx={{ bottom: 72 }}
      />
    </Box>
  );
}

export default DiscoverPage;

import { useState } from "react";
import {
  Box,
  Button,
  Stack,
  List,
  ListItem,
  ListItemText,
  IconButton,
  Typography,
  CircularProgress,
  Alert,
} from "@mui/material";
import {
  Refresh as RefreshIcon,
  ContentCopy as CopyIcon,
  Edit as EditIcon,
  Folder as FolderIcon,
} from "@mui/icons-material";
import { invoke } from "@tauri-apps/api/core";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { useSnackbar } from "../hooks";

interface DiscoveredHost {
  name: string;
  ip: string;
  port: number;
  serviceType: string;
}

function DiscoverPage() {
  const [hosts, setHosts] = useState<DiscoveredHost[]>([]);
  const [isDiscovering, setIsDiscovering] = useState(false);
  const { showSnackbar } = useSnackbar();

  const handleDiscover = async () => {
    setIsDiscovering(true);
    setHosts([]);

    try {
      const [transferHosts, collabHosts] = await Promise.all([
        invoke<DiscoveredHost[]>("discover_hosts"),
        invoke<DiscoveredHost[]>("discover_collab_hosts"),
      ]);

      const allHosts = [...transferHosts, ...collabHosts];
      setHosts(allHosts);

      if (allHosts.length === 0) {
        showSnackbar("No hosts found");
      } else {
        showSnackbar(`Found ${allHosts.length} host(s)`);
      }
    } catch (error) {
      console.error("Failed to discover hosts:", error);
      showSnackbar(`Discovery failed: ${error}`, "error");
    } finally {
      setIsDiscovering(false);
    }
  };

  const handleCopyIp = async (host: DiscoveredHost) => {
    const ipPart = isIpv6(host.ip) ? `[${host.ip}]` : host.ip;
    const text =
      host.serviceType === "collab" ? `${ipPart}:${host.port}` : host.ip;
    await writeText(text);
    showSnackbar(`Copied ${text}`);
  };

  const isIpv6 = (ip: string) => ip.includes(":");

  return (
    <Stack spacing={2}>
      <Box
        sx={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
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
        <Alert severity="info">
          Click "Discover" to find hosts on your local network
        </Alert>
      )}

      {hosts.length > 0 && (
        <List sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
          {hosts.map((host, index) => (
            <ListItem
              key={index}
              sx={{
                bgcolor: "background.paper",
                borderRadius: 1,
                border: "1px solid",
                borderColor: "divider",
              }}
              secondaryAction={
                <IconButton
                  edge="end"
                  onClick={() => handleCopyIp(host)}
                  color="primary"
                >
                  <CopyIcon />
                </IconButton>
              }
            >
              <ListItemText
                primary={
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    {host.name || "Unknown Host"}
                    {host.serviceType === "collab" ? (
                      <EditIcon fontSize="small" color="primary" />
                    ) : (
                      <FolderIcon fontSize="small" color="primary" />
                    )}
                  </Box>
                }
                secondary={
                  host.serviceType === "collab"
                    ? `${isIpv6(host.ip) ? `[${host.ip}]` : host.ip}:${host.port}`
                    : host.ip
                }
                slotProps={{
                  primary: { fontWeight: "medium" },
                }}
              />
            </ListItem>
          ))}
        </List>
      )}
    </Stack>
  );
}

export default DiscoverPage;

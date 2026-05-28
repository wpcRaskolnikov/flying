import { useState } from "react";
import {
  Box,
  ThemeProvider,
  createTheme,
  CssBaseline,
  Paper,
  BottomNavigation,
  BottomNavigationAction,
} from "@mui/material";
import {
  Search as SearchIcon,
  Send as SendIcon,
  Download as DownloadIcon,
  Edit as EditIcon,
  Settings as SettingsIcon,
} from "@mui/icons-material";
import {
  DiscoverPage,
  SendPage,
  ReceivePage,
  SettingsPage,
  CollabEditPage,
} from "./pages";

const tabs = [
  { label: "Discover", icon: <SearchIcon />, component: <DiscoverPage /> },
  { label: "Send", icon: <SendIcon />, component: <SendPage /> },
  { label: "Receive", icon: <DownloadIcon />, component: <ReceivePage /> },
  { label: "Collab", icon: <EditIcon />, component: <CollabEditPage /> },
  { label: "Settings", icon: <SettingsIcon />, component: <SettingsPage /> },
];

const theme = createTheme({
  palette: {
    mode: "light",
    primary: {
      main: "#1976d2",
    },
  },
});

function App() {
  const [currentTab, setCurrentTab] = useState(0);

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Box
        sx={{
          display: "flex",
          flexDirection: "column",
          height: "100vh",
          bgcolor: "#f5f5f5",
        }}
      >
        {/* Main content area */}
        <Box
          sx={{
            flexGrow: 1,
            overflow: "auto",
            pb: 7,
            pt: "env(safe-area-inset-top)",
            pl: "env(safe-area-inset-left)",
            pr: "env(safe-area-inset-right)",
          }}
        >
          {tabs.map((tab, index) => (
            <Box key={index} hidden={currentTab !== index}>
              {tab.component}
            </Box>
          ))}
        </Box>

        {/* Bottom Navigation */}
        <Paper
          sx={{
            position: "fixed",
            bottom: 0,
            left: 0,
            right: 0,
            pb: "env(safe-area-inset-bottom)",
            pl: "env(safe-area-inset-left)",
            pr: "env(safe-area-inset-right)",
          }}
          elevation={3}
        >
          <BottomNavigation
            value={currentTab}
            onChange={(_event, newValue) => setCurrentTab(newValue)}
            showLabels
          >
            {tabs.map((tab, index) => (
              <BottomNavigationAction
                key={index}
                label={tab.label}
                icon={tab.icon}
              />
            ))}
          </BottomNavigation>
        </Paper>
      </Box>
    </ThemeProvider>
  );
}

export default App;

import { useState } from "react";
import {
  Box,
  ThemeProvider,
  createTheme,
  CssBaseline,
  BottomNavigation,
  BottomNavigationAction,
  Paper,
} from "@mui/material";
import {
  Search as SearchIcon,
  Send as SendIcon,
  Download as DownloadIcon,
} from "@mui/icons-material";
import { DiscoverPage, SendPage, ReceivePage } from "./pages";

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
          }}
        >
          <Box sx={{ display: currentTab === 0 ? "block" : "none" }}>
            <DiscoverPage />
          </Box>
          <Box sx={{ display: currentTab === 1 ? "block" : "none" }}>
            <SendPage />
          </Box>
          <Box sx={{ display: currentTab === 2 ? "block" : "none" }}>
            <ReceivePage />
          </Box>
        </Box>

        {/* Bottom Navigation */}
        <Paper
          sx={{
            position: "fixed",
            bottom: 0,
            left: 0,
            right: 0,
            pb: "env(safe-area-inset-bottom)",
          }}
          elevation={3}
        >
          <BottomNavigation
            value={currentTab}
            onChange={(_event, newValue) => {
              setCurrentTab(newValue);
            }}
            showLabels
          >
            <BottomNavigationAction label="Discover" icon={<SearchIcon />} />
            <BottomNavigationAction label="Send" icon={<SendIcon />} />
            <BottomNavigationAction label="Receive" icon={<DownloadIcon />} />
          </BottomNavigation>
        </Paper>
      </Box>
    </ThemeProvider>
  );
}

export default App;

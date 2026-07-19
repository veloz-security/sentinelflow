import { createTheme } from '@mui/material/styles';

export const semanticTokens = Object.freeze({
  neutral: {
    foreground: 'oklch(0.40 0.018 285)',
    background: 'oklch(0.945 0.009 285)',
    border: 'oklch(0.82 0.014 285)',
  },
  info: {
    foreground: 'oklch(0.40 0.105 245)',
    background: 'oklch(0.955 0.025 245)',
    border: 'oklch(0.78 0.07 245)',
  },
  positive: {
    foreground: 'oklch(0.38 0.09 155)',
    background: 'oklch(0.95 0.035 155)',
    border: 'oklch(0.76 0.075 155)',
  },
  warning: {
    foreground: 'oklch(0.40 0.10 72)',
    background: 'oklch(0.955 0.035 82)',
    border: 'oklch(0.76 0.085 76)',
  },
  critical: {
    foreground: 'oklch(0.40 0.13 28)',
    background: 'oklch(0.955 0.03 28)',
    border: 'oklch(0.77 0.08 28)',
  },
  provenance: {
    observed: 'oklch(0.44 0.08 245)',
    deterministic: 'oklch(0.42 0.095 155)',
    ai: 'oklch(0.43 0.10 305)',
    human: 'oklch(0.43 0.105 72)',
    enforcement: 'oklch(0.42 0.11 28)',
  },
});

export const layoutTokens = Object.freeze({
  sidebarWidth: 256,
  contentMaxWidth: 1440,
  headerHeight: 64,
});

export const appTheme = createTheme({
  cssVariables: {
    cssVarPrefix: 'sf',
    nativeColor: true,
  },
  palette: {
    mode: 'light',
    primary: {
      main: '#a7412b',
      dark: '#793124',
      light: '#f1d9d1',
      contrastText: '#fffdf9',
    },
    secondary: {
      main: '#604c7c',
      contrastText: '#fffdf9',
    },
    success: {
      main: '#247447',
    },
    warning: {
      main: '#79570d',
    },
    error: {
      main: '#903329',
    },
    info: {
      main: '#266285',
    },
    background: {
      default: '#f7f4ef',
      paper: '#fffdf9',
    },
    text: {
      primary: '#25242d',
      secondary: '#5e5c69',
    },
    divider: '#d8d5dd',
    action: {
      hover: '#f4e8e3',
      selected: '#f1d9d1',
      disabled: '#8b8992',
      disabledBackground: '#e5e3e8',
    },
  },
  shape: {
    borderRadius: 10,
  },
  spacing: 8,
  typography: {
    fontFamily:
      '-apple-system, BlinkMacSystemFont, "Segoe UI", Inter, system-ui, sans-serif',
    h1: {
      fontSize: '2rem',
      lineHeight: 1.18,
      fontWeight: 760,
      letterSpacing: '-0.028em',
    },
    h2: {
      fontSize: '1.35rem',
      lineHeight: 1.3,
      fontWeight: 720,
      letterSpacing: '-0.016em',
    },
    h3: {
      fontSize: '1.05rem',
      lineHeight: 1.35,
      fontWeight: 700,
    },
    subtitle1: {
      fontSize: '0.95rem',
      lineHeight: 1.45,
      fontWeight: 650,
    },
    body1: {
      fontSize: '0.925rem',
      lineHeight: 1.62,
    },
    body2: {
      fontSize: '0.8125rem',
      lineHeight: 1.55,
    },
    caption: {
      fontSize: '0.75rem',
      lineHeight: 1.45,
      letterSpacing: '0.012em',
    },
    overline: {
      fontSize: '0.6875rem',
      lineHeight: 1.4,
      fontWeight: 760,
      letterSpacing: '0.09em',
    },
    button: {
      textTransform: 'none',
      fontSize: '0.8375rem',
      fontWeight: 700,
    },
  },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          minWidth: 320,
          minHeight: '100vh',
          textRendering: 'optimizeLegibility',
        },
        '#root': {
          minHeight: '100vh',
        },
        code: {
          fontFamily:
            'ui-monospace, "SFMono-Regular", Consolas, "Liberation Mono", monospace',
          fontSize: '0.9em',
        },
        '*:focus-visible': {
          outline: '3px solid oklch(0.58 0.17 42)',
          outlineOffset: 3,
        },
        '@media (prefers-reduced-motion: reduce)': {
          '*, *::before, *::after': {
            scrollBehavior: 'auto !important',
            animationDuration: '0.01ms !important',
            animationIterationCount: '1 !important',
            transitionDuration: '0.01ms !important',
          },
        },
      },
    },
    MuiButton: {
      defaultProps: {
        disableElevation: true,
      },
      styleOverrides: {
        root: {
          minHeight: 38,
          borderRadius: 8,
          paddingInline: 14,
        },
      },
    },
    MuiCard: {
      defaultProps: {
        elevation: 0,
      },
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          borderColor: 'oklch(0.86 0.012 285)',
          boxShadow: '0 10px 28px oklch(0.28 0.02 285 / 0.055)',
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: {
          height: 26,
          borderRadius: 7,
          fontWeight: 680,
        },
        label: {
          paddingInline: 9,
        },
      },
    },
    MuiAlert: {
      styleOverrides: {
        root: {
          border: '1px solid currentColor',
          borderRadius: 9,
          alignItems: 'center',
        },
      },
    },
    MuiListItemButton: {
      styleOverrides: {
        root: {
          minHeight: 42,
          borderRadius: 8,
          transition: 'background-color 180ms cubic-bezier(0.22, 1, 0.36, 1)',
        },
      },
    },
    MuiSkeleton: {
      defaultProps: {
        animation: 'wave',
      },
      styleOverrides: {
        root: {
          backgroundColor: 'oklch(0.90 0.009 285)',
        },
      },
    },
    MuiTooltip: {
      defaultProps: {
        arrow: true,
      },
    },
  },
});

import {
  Box,
  Button,
  Divider,
  List,
  ListItem,
  ListItemButton,
  ListItemText,
  ListSubheader,
  Stack,
  Toolbar,
  Typography,
} from '@mui/material';
import type { PropsWithChildren } from 'react';
import { Link as RouterLink, useLocation } from 'react-router-dom';
import { layoutTokens } from '../theme';
import { StatusBadge } from '../components/StatusBadge';

interface NavigationItem {
  readonly label: string;
  readonly shortLabel: string;
  readonly path: string;
}

interface NavigationGroup {
  readonly label: string;
  readonly items: readonly NavigationItem[];
}

const liveNavigationGroups = [
  {
    label: 'Workspace',
    items: [
      { label: 'Overview', shortLabel: 'Overview', path: '/' },
      { label: 'Incidents', shortLabel: 'Incidents', path: '/incidents' },
    ],
  },
  {
    label: 'Review',
    items: [
      { label: 'Validation', shortLabel: 'Validation', path: '/validation' },
      {
        label: 'Authorization',
        shortLabel: 'Authorize',
        path: '/authorization',
      },
      { label: 'Enforcement', shortLabel: 'Enforcement', path: '/enforcement' },
    ],
  },
  {
    label: 'System',
    items: [
      { label: 'Audit ledger', shortLabel: 'Audit', path: '/audit' },
      { label: 'Session security', shortLabel: 'Session', path: '/session' },
    ],
  },
] as const satisfies readonly NavigationGroup[];

const fixtureNavigationGroups = [
  {
    label: 'Fixture workspace',
    items: [
      { label: 'Overview', shortLabel: 'Overview', path: '/fixtures' },
      {
        label: 'Incidents',
        shortLabel: 'Incidents',
        path: '/fixtures/incidents',
      },
      {
        label: 'Validation',
        shortLabel: 'Validation',
        path: '/fixtures/validation',
      },
      {
        label: 'Authorization',
        shortLabel: 'Authorize',
        path: '/fixtures/authorization',
      },
      {
        label: 'Enforcement',
        shortLabel: 'Enforcement',
        path: '/fixtures/enforcement',
      },
    ],
  },
  {
    label: 'System',
    items: [{ label: 'State library', shortLabel: 'States', path: '/states' }],
  },
] as const satisfies readonly NavigationGroup[];

function flattenNavigation(groups: readonly NavigationGroup[]) {
  return groups.reduce<NavigationItem[]>(
    (items, group) => [...items, ...group.items],
    [],
  );
}

function isSelected(pathname: string, path: string) {
  return path === '/' || path === '/fixtures'
    ? pathname === path
    : pathname.startsWith(path);
}

function DesktopNavigation({
  pathname,
  groups,
  mode,
  actor,
}: {
  readonly pathname: string;
  readonly groups: readonly NavigationGroup[];
  readonly mode: 'live' | 'fixture';
  readonly actor?: string;
}) {
  return (
    <Box
      component="aside"
      data-testid="desktop-sidebar"
      sx={{
        display: { xs: 'none', md: 'flex' },
        position: 'sticky',
        top: 0,
        height: '100vh',
        flexDirection: 'column',
        borderRight: 1,
        borderColor: 'divider',
        bgcolor: 'oklch(0.945 0.009 285)',
      }}
    >
      <Stack
        direction="row"
        spacing={1.25}
        alignItems="center"
        sx={{ px: 2.5, py: 2.25 }}
      >
        <Box
          aria-hidden="true"
          sx={{
            display: 'grid',
            placeItems: 'center',
            width: 32,
            height: 32,
            borderRadius: 1.25,
            bgcolor: 'primary.main',
            color: 'primary.contrastText',
            fontSize: '0.72rem',
            fontWeight: 800,
            letterSpacing: '0.05em',
          }}
        >
          SF
        </Box>
        <Box>
          <Typography sx={{ fontWeight: 780, letterSpacing: '-0.018em' }}>
            SentinelFlow
          </Typography>
          <Typography variant="caption" color="text.secondary">
            Review workspace
          </Typography>
        </Box>
      </Stack>

      <Divider />

      <Box
        component="nav"
        aria-label="Primary"
        sx={{ flex: 1, px: 1.5, py: 1.5 }}
      >
        {groups.map((group) => (
          <List
            key={group.label}
            dense
            disablePadding
            subheader={
              <ListSubheader
                disableSticky
                component="li"
                sx={{
                  px: 1.25,
                  pt: 1.5,
                  pb: 0.5,
                  bgcolor: 'transparent',
                  color: 'text.secondary',
                  fontSize: '0.66rem',
                  fontWeight: 760,
                  letterSpacing: '0.09em',
                  lineHeight: 1.5,
                  textTransform: 'uppercase',
                }}
              >
                {group.label}
              </ListSubheader>
            }
          >
            {group.items.map((item) => {
              const selected = isSelected(pathname, item.path);
              return (
                <ListItem key={item.path} disablePadding>
                  <ListItemButton
                    component={RouterLink}
                    to={item.path}
                    selected={selected}
                    aria-current={selected ? 'page' : undefined}
                    sx={{
                      mb: 0.25,
                      '&.Mui-selected': {
                        color: 'primary.dark',
                        bgcolor: 'action.selected',
                      },
                      '&.Mui-selected:hover': { bgcolor: 'action.selected' },
                    }}
                  >
                    <Box
                      aria-hidden="true"
                      sx={{
                        width: 7,
                        height: 7,
                        mr: 1.5,
                        borderRadius: '50%',
                        bgcolor: selected ? 'primary.main' : 'divider',
                      }}
                    />
                    <ListItemText
                      primary={item.label}
                      primaryTypographyProps={{
                        variant: 'body2',
                        fontWeight: selected ? 720 : 590,
                      }}
                    />
                  </ListItemButton>
                </ListItem>
              );
            })}
          </List>
        ))}
      </Box>

      <Box sx={{ p: 2 }}>
        <Box
          sx={{
            p: 1.5,
            border: 1,
            borderColor: 'divider',
            borderRadius: 1.5,
            bgcolor: 'background.paper',
          }}
        >
          <StatusBadge
            label={mode === 'live' ? 'Management API' : 'Fixture environment'}
            tone={mode === 'live' ? 'positive' : 'neutral'}
          />
          <Typography
            variant="caption"
            color="text.secondary"
            sx={{ display: 'block', mt: 1 }}
          >
            {mode === 'live'
              ? `${actor ?? 'Authenticated administrator'} · guarded review session`
              : 'Typed data only. No API, HIL, or executor authority.'}
          </Typography>
        </Box>
      </Box>
    </Box>
  );
}

function NarrowNavigation({
  pathname,
  items,
}: {
  readonly pathname: string;
  readonly items: readonly NavigationItem[];
}) {
  return (
    <Box
      component="nav"
      aria-label="Primary"
      data-testid="narrow-navigation"
      sx={{
        display: { xs: 'flex', md: 'none' },
        gap: 0.5,
        px: 2,
        py: 1,
        overflowX: 'auto',
        borderBottom: 1,
        borderColor: 'divider',
        bgcolor: 'background.paper',
      }}
    >
      {items.map((item) => {
        const selected = isSelected(pathname, item.path);
        return (
          <Button
            key={item.path}
            component={RouterLink}
            to={item.path}
            aria-current={selected ? 'page' : undefined}
            variant={selected ? 'contained' : 'text'}
            size="small"
            sx={{ flexShrink: 0 }}
          >
            {item.shortLabel}
          </Button>
        );
      })}
    </Box>
  );
}

export interface AppShellProps extends PropsWithChildren {
  readonly mode?: 'live' | 'fixture';
  readonly actor?: string;
  readonly streamState?: string;
}

export function AppShell({
  children,
  mode = 'fixture',
  actor,
  streamState = 'offline',
}: AppShellProps) {
  const location = useLocation();
  const groups =
    mode === 'live' ? liveNavigationGroups : fixtureNavigationGroups;
  const flatNavigation = flattenNavigation(groups);
  const currentPage =
    flatNavigation.find((item) => isSelected(location.pathname, item.path))
      ?.label ??
    (location.pathname.startsWith('/policies/')
      ? 'Policy detail'
      : location.pathname.startsWith('/enforcement-actions/')
        ? 'Enforcement action'
        : 'Unknown route');

  return (
    <Box
      sx={{
        minHeight: '100vh',
        display: 'grid',
        gridTemplateColumns: {
          xs: 'minmax(0, 1fr)',
          md: `${layoutTokens.sidebarWidth}px minmax(0, 1fr)`,
        },
      }}
    >
      <Box
        component="a"
        href="#main-content"
        sx={{
          position: 'fixed',
          left: 12,
          top: 8,
          zIndex: (theme) => theme.zIndex.tooltip + 1,
          bgcolor: 'background.paper',
          color: 'primary.dark',
          px: 2,
          py: 1,
          border: 1,
          borderColor: 'primary.main',
          borderRadius: 1,
          transform: 'translateY(-160%)',
          transition: 'transform 180ms cubic-bezier(0.22, 1, 0.36, 1)',
          '&:focus': { transform: 'translateY(0)' },
        }}
      >
        Skip to content
      </Box>

      <DesktopNavigation
        pathname={location.pathname}
        groups={groups}
        mode={mode}
        actor={actor}
      />

      <Box
        sx={{
          minWidth: 0,
          display: 'flex',
          minHeight: '100vh',
          flexDirection: 'column',
        }}
      >
        <Box
          component="header"
          sx={{
            position: 'sticky',
            top: 0,
            zIndex: (theme) => theme.zIndex.appBar,
            bgcolor: 'oklch(0.989 0.004 78 / 0.96)',
            borderBottom: 1,
            borderColor: 'divider',
          }}
        >
          <Toolbar
            sx={{
              minHeight: `${layoutTokens.headerHeight}px !important`,
              px: { xs: 2, md: 4 },
            }}
          >
            <Stack
              direction="row"
              spacing={1}
              alignItems="center"
              sx={{ minWidth: 0, flex: 1 }}
            >
              <Typography
                sx={{
                  display: { xs: 'block', md: 'none' },
                  fontWeight: 780,
                  mr: 1,
                }}
              >
                SentinelFlow
              </Typography>
              <Typography
                variant="body2"
                color="text.secondary"
                sx={{ display: { xs: 'none', sm: 'block' } }}
              >
                Workspace
              </Typography>
              <Typography
                aria-hidden="true"
                color="text.secondary"
                sx={{ display: { xs: 'none', sm: 'block' } }}
              >
                /
              </Typography>
              <Typography
                variant="body2"
                sx={{
                  fontWeight: 720,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }}
              >
                {currentPage}
              </Typography>
            </Stack>
            <Stack direction="row" spacing={1} alignItems="center">
              <Box sx={{ display: { xs: 'none', lg: 'block' } }}>
                <StatusBadge
                  label={
                    mode === 'live'
                      ? `Stream ${streamState}`
                      : 'Source health explicit'
                  }
                  tone={
                    mode === 'live' && streamState === 'connected'
                      ? 'positive'
                      : 'info'
                  }
                />
              </Box>
              <StatusBadge
                label={mode === 'live' ? 'Live REST' : 'Fixture'}
                tone={mode === 'live' ? 'positive' : 'neutral'}
                ariaLabel={
                  mode === 'live'
                    ? 'Live management data mode'
                    : 'Fixture data mode'
                }
              />
            </Stack>
          </Toolbar>
          <NarrowNavigation
            pathname={location.pathname}
            items={flatNavigation}
          />
        </Box>

        <Box
          id="main-content"
          component="main"
          tabIndex={-1}
          sx={{
            width: '100%',
            maxWidth: layoutTokens.contentMaxWidth,
            mx: 'auto',
            flex: 1,
            px: { xs: 2, sm: 3, md: 4, lg: 5 },
            py: { xs: 3, md: 4.5 },
          }}
        >
          {children}
        </Box>

        <Box
          component="footer"
          sx={{
            borderTop: 1,
            borderColor: 'divider',
            px: { xs: 2, md: 4 },
            py: 2,
          }}
        >
          <Typography variant="caption" color="text.secondary">
            {mode === 'live'
              ? 'Authenticated same-origin management reads. Live events trigger REST invalidation only; this UI has no HIL or executor authority.'
              : 'Frozen contract fixtures. No live traffic, credentials, or enforcement authority.'}
          </Typography>
        </Box>
      </Box>
    </Box>
  );
}

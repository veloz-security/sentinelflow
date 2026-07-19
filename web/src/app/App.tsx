import { CssBaseline, ThemeProvider } from '@mui/material';
import { lazy, Suspense } from 'react';
import { Route, Routes, useLocation } from 'react-router-dom';
import { NotFoundPage } from '../pages/NotFoundPage';
import { appTheme } from '../theme';
import { BootstrapPage, LoginPage, SessionPage } from '../live/AuthPages';
import { LiveUpdatesProvider } from '../live/LiveUpdatesProvider';
import { useLiveUpdates } from '../live/liveUpdatesContext';
import { SessionProvider } from '../live/SessionProvider';
import { useSession } from '../live/sessionContext';
import { AppShell } from './AppShell';

const OverviewPage = lazy(async () => {
  const page = await import('../pages/OverviewPage');
  return { default: page.OverviewPage };
});
const StateMatrixPage = lazy(async () => {
  const page = await import('../pages/StateMatrixPage');
  return { default: page.StateMatrixPage };
});
const IncidentListPage = lazy(async () => {
  const page = await import('../pages/IncidentListPage');
  return { default: page.IncidentListPage };
});
const IncidentListStatePage = lazy(async () => {
  const page = await import('../pages/IncidentListStatePage');
  return { default: page.IncidentListStatePage };
});
const IncidentsPage = lazy(async () => {
  const page = await import('../pages/IncidentsPage');
  return { default: page.IncidentsPage };
});
const IncidentDetailStatePage = lazy(async () => {
  const page = await import('../pages/IncidentDetailStatePage');
  return { default: page.IncidentDetailStatePage };
});
const ValidationPage = lazy(async () => {
  const page = await import('../pages/ValidationPage');
  return { default: page.ValidationPage };
});
const ValidationReviewStatePage = lazy(async () => {
  const page = await import('../pages/ValidationReviewStatePage');
  return { default: page.ValidationReviewStatePage };
});
const HilAuthorizationPage = lazy(async () => {
  const page = await import('../pages/HilAuthorizationPage');
  return { default: page.HilAuthorizationPage };
});
const HilAuthorizationStatePage = lazy(async () => {
  const page = await import('../pages/HilAuthorizationStatePage');
  return { default: page.HilAuthorizationStatePage };
});
const EnforcementPage = lazy(async () => {
  const page = await import('../pages/EnforcementPage');
  return { default: page.EnforcementPage };
});
const EnforcementLifecycleStatePage = lazy(async () => {
  const page = await import('../pages/EnforcementLifecycleStatePage');
  return { default: page.EnforcementLifecycleStatePage };
});
const LiveIncidentListPage = lazy(async () => {
  const page = await import('../live/IncidentPages');
  return { default: page.LiveIncidentListPage };
});
const LiveIncidentDetailPage = lazy(async () => {
  const page = await import('../live/IncidentPages');
  return { default: page.LiveIncidentDetailPage };
});
const LiveOverviewPage = lazy(async () => {
  const page = await import('../live/ReviewPages');
  return { default: page.LiveOverviewPage };
});
const ResourceLookupPage = lazy(async () => {
  const page = await import('../live/ReviewPages');
  return { default: page.ResourceLookupPage };
});
const LivePolicyPage = lazy(async () => {
  const page = await import('../live/ReviewPages');
  return { default: page.LivePolicyPage };
});
const LiveEnforcementActionPage = lazy(async () => {
  const page = await import('../live/ReviewPages');
  return { default: page.LiveEnforcementActionPage };
});
const LiveAuditPage = lazy(async () => {
  const page = await import('../live/ReviewPages');
  return { default: page.LiveAuditPage };
});

function LoadingInterface() {
  return (
    <div role="status" aria-live="polite" aria-busy="true">
      Loading interface
    </div>
  );
}

function FixtureApplication() {
  return (
    <AppShell mode="fixture">
      <Suspense fallback={<LoadingInterface />}>
        <Routes>
          <Route path="/fixtures" element={<OverviewPage />} />
          <Route path="/fixtures/incidents" element={<IncidentListPage />} />
          <Route
            path="/fixtures/incidents/:incidentId"
            element={<IncidentsPage />}
          />
          <Route path="/fixtures/validation" element={<ValidationPage />} />
          <Route
            path="/fixtures/authorization"
            element={<HilAuthorizationPage />}
          />
          <Route path="/fixtures/enforcement" element={<EnforcementPage />} />
          <Route path="/states" element={<StateMatrixPage />} />
          <Route
            path="/states/incidents/:stateName"
            element={<IncidentListStatePage />}
          />
          <Route
            path="/states/incident-detail/:stateName"
            element={<IncidentDetailStatePage />}
          />
          <Route
            path="/states/validation/:stateName"
            element={<ValidationReviewStatePage />}
          />
          <Route
            path="/states/hil/:stateName"
            element={<HilAuthorizationStatePage />}
          />
          <Route
            path="/states/enforcement/:stateName"
            element={<EnforcementLifecycleStatePage />}
          />
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </Suspense>
    </AppShell>
  );
}

function LiveShell() {
  const session = useSession();
  const updates = useLiveUpdates();
  return (
    <AppShell
      mode="live"
      actor={session.session?.actor_id}
      streamState={updates.state}
    >
      <Suspense fallback={<LoadingInterface />}>
        <Routes>
          <Route path="/" element={<LiveOverviewPage />} />
          <Route path="/incidents" element={<LiveIncidentListPage />} />
          <Route
            path="/incidents/:incidentId"
            element={<LiveIncidentDetailPage />}
          />
          <Route
            path="/validation"
            element={<ResourceLookupPage kind="policy" />}
          />
          <Route
            path="/authorization"
            element={<ResourceLookupPage kind="policy" />}
          />
          <Route path="/policies/:policyId" element={<LivePolicyPage />} />
          <Route
            path="/enforcement"
            element={<ResourceLookupPage kind="action" />}
          />
          <Route
            path="/enforcement-actions/:actionId"
            element={<LiveEnforcementActionPage />}
          />
          <Route path="/audit" element={<LiveAuditPage />} />
          <Route path="/session" element={<SessionPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </Suspense>
    </AppShell>
  );
}

function LiveApplication() {
  const session = useSession();
  if (session.phase === 'bootstrapping' || session.phase === 'error') {
    return <BootstrapPage />;
  }
  if (session.phase === 'anonymous') {
    return <LoginPage />;
  }
  return (
    <LiveUpdatesProvider>
      <LiveShell />
    </LiveUpdatesProvider>
  );
}

export function App() {
  const location = useLocation();
  const fixtureRoute =
    location.pathname === '/fixtures' ||
    location.pathname.startsWith('/fixtures/') ||
    location.pathname === '/states' ||
    location.pathname.startsWith('/states/');
  return (
    <ThemeProvider theme={appTheme}>
      <CssBaseline />
      {fixtureRoute ? (
        <FixtureApplication />
      ) : (
        <SessionProvider>
          <LiveApplication />
        </SessionProvider>
      )}
    </ThemeProvider>
  );
}

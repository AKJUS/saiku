/*
 *   Copyright 2026 Spicule Ltd
 *   Apache License, Version 2.0.
 */
package org.saiku.web.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.saiku.datasources.connection.ISaikuConnection;
import org.saiku.datasources.datasource.SaikuDatasource;
import org.saiku.service.ISessionService;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * saiku#1948 (F1, CWE-863) reversion guard for {@link SecurityAwareConnectionManager}'s
 * connection-cache keying — the shared-connection role race.
 *
 * <p>Before the fix the manager keyed a security-enabled datasource's connection {@code name +
 * "-" + username} ONLY when the session map carried a {@code "username"} (populated exclusively by
 * the UI {@code /session} login). A pure XMLA client (HTTP Basic, stateless {@code /xmla/**} chain,
 * no UI login) has no such entry, so EVERY authenticated XMLA caller collapsed onto the SAME
 * bare-{@code name} connection; {@code applySecurity} then mutated that one connection's Mondrian
 * role per request and Mondrian read it live during evaluation, letting a concurrent request flip
 * another user's in-flight query to a different role scope.
 *
 * <p>These tests drive {@link SecurityAwareConnectionManager#resolveConnectionKey} — the exact site
 * that decides connection isolation — with a fake {@link ISessionService} and a seeded {@link
 * SecurityContextHolder}. Distinct keys prove distinct cache slots, hence distinct connections and
 * per-user roles. Reverting the F1 fix flips {@link #xmlaNoSessionUsername_keysPerPrincipal()} and
 * {@link #xmlaDistinctPrincipals_getDistinctKeys()} from green to red (both would collapse to the
 * bare {@code name}).
 *
 * <p>Also pins the two invariants the rework must preserve: the REST path (session {@code
 * "username"} present) is keyed byte-for-byte as before, and a security-DISABLED datasource still
 * resolves to the bare {@code name} for everyone — so no user's role can stick to another's
 * connection.
 */
public class SecurityAwareConnectionManagerKeyingTest {

    private static final String DS = "foodmart";

    @Before
    public void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @After
    public void tearDown() {
        SecurityContextHolder.clearContext();
    }

    private static SaikuDatasource datasource(boolean securityEnabled) {
        Properties props = new Properties();
        props.setProperty(ISaikuConnection.SECURITY_ENABLED_KEY, Boolean.toString(securityEnabled));
        return new SaikuDatasource(DS, SaikuDatasource.Type.OLAP, props);
    }

    private static SecurityAwareConnectionManager managerWithSession(Map<String, Object> session) {
        SecurityAwareConnectionManager mgr = new SecurityAwareConnectionManager();
        mgr.setSessionService(new FakeSessionService(session));
        return mgr;
    }

    private static void authenticateAs(String user) {
        SecurityContextHolder.getContext()
                .setAuthentication(new UsernamePasswordAuthenticationToken(
                        user, "n/a", Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"))));
    }

    /** REST always carries a session "username" — that path must be keyed exactly as before. */
    @Test
    public void restWithSessionUsername_keyUnchanged() {
        Map<String, Object> session = new HashMap<>();
        session.put("username", "alice");
        SecurityAwareConnectionManager mgr = managerWithSession(session);
        // Even if a SecurityContext principal is also present, the session username wins (unchanged).
        authenticateAs("someone-else");

        assertEquals("foodmart-alice", mgr.resolveConnectionKey(DS, datasource(true)));
    }

    /**
     * F1: an XMLA/Basic caller has no session "username" but a real principal — key per principal so
     * the connection (and its role) is isolated. Pre-fix this collapsed to the bare name.
     */
    @Test
    public void xmlaNoSessionUsername_keysPerPrincipal() {
        SecurityAwareConnectionManager mgr = managerWithSession(new HashMap<>());
        authenticateAs("bob");

        assertEquals("foodmart-bob", mgr.resolveConnectionKey(DS, datasource(true)));
    }

    /** F1 core: two distinct principals must NOT share a cache slot (hence not a connection). */
    @Test
    public void xmlaDistinctPrincipals_getDistinctKeys() {
        SecurityAwareConnectionManager mgr = managerWithSession(new HashMap<>());

        authenticateAs("bob");
        String bobKey = mgr.resolveConnectionKey(DS, datasource(true));

        authenticateAs("carol");
        String carolKey = mgr.resolveConnectionKey(DS, datasource(true));

        assertEquals("foodmart-bob", bobKey);
        assertEquals("foodmart-carol", carolKey);
        assertNotEquals("distinct XMLA principals must get distinct connection keys", bobKey, carolKey);
    }

    /** No authenticated principal (and no session username) → bare name. Anonymous /xmla is already
     * blocked by saiku#1905, so this is only a fail-safe. */
    @Test
    public void unauthenticated_bareName() {
        SecurityAwareConnectionManager mgr = managerWithSession(new HashMap<>());
        // SecurityContext cleared by @Before.
        assertEquals("foodmart", mgr.resolveConnectionKey(DS, datasource(true)));
    }

    /** An anonymous token is not a real principal — bare name (fail-safe). */
    @Test
    public void anonymous_bareName() {
        SecurityAwareConnectionManager mgr = managerWithSession(new HashMap<>());
        SecurityContextHolder.getContext()
                .setAuthentication(new AnonymousAuthenticationToken(
                        "key",
                        "anonymousUser",
                        Collections.singletonList(new SimpleGrantedAuthority("ROLE_ANONYMOUS"))));

        assertEquals("foodmart", mgr.resolveConnectionKey(DS, datasource(true)));
    }

    /**
     * A security-DISABLED datasource resolves to the bare name for everyone — no per-principal
     * keying, and applySecurity never sets a role there, so one user's role can never stick to
     * another's connection. Guards against re-introducing the sticky-role regression.
     */
    @Test
    public void securityDisabled_bareName_regardlessOfPrincipal() {
        SecurityAwareConnectionManager mgr = managerWithSession(new HashMap<>());
        authenticateAs("bob");

        assertEquals("foodmart", mgr.resolveConnectionKey(DS, datasource(false)));
    }

    /** Minimal ISessionService fake — resolveConnectionKey only reads getAllSessionObjects(). */
    private static final class FakeSessionService implements ISessionService {
        private final Map<String, Object> session;

        FakeSessionService(Map<String, Object> session) {
            this.session = session;
        }

        @Override
        public Map<String, Object> getAllSessionObjects() {
            return session;
        }

        @Override
        public Map<String, Object> login(HttpServletRequest req, String username, String password) {
            return null;
        }

        @Override
        public void logout(HttpServletRequest req) {}

        @Override
        public void authenticate(HttpServletRequest req, String username, String password) {}

        @Override
        public Map<String, Object> getSession() {
            return session;
        }

        @Override
        public void clearSessions(HttpServletRequest req, String username, String password) {}
    }
}

/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.config;

import com.wireguard.util.NonNullForAll;
import com.wireguard.util.SimpleDns;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import androidx.annotation.Nullable;


/**
 * An external endpoint (host and port) used to connect to a WireGuard {@link Peer}.
 * <p>
 * Instances of this class are externally immutable.
 */
@NonNullForAll
public final class InetEndpoint {
    private static final Pattern BARE_IPV6 = Pattern.compile("^[^\\[\\]]*:[^\\[\\]]*");
    private static final Pattern FORBIDDEN_CHARACTERS = Pattern.compile("[/?#]");
    private static final Pattern IPV4_PORT_PATTERN = Pattern.compile("^(\\d{1,3}(?:\\.\\d{1,3}){3}):(\\d{1,5})$");

    private final String host;
    private final boolean isResolved;
    private final Object lock = new Object();
    private final int port;
    private Instant lastResolution = Instant.EPOCH;
    @Nullable private InetEndpoint resolved;

    private InetEndpoint(final String host, final boolean isResolved, final int port) {
        this.host = host;
        this.isResolved = isResolved;
        this.port = port;
    }

    public static InetEndpoint parse(final String endpoint) throws ParseException {
        if (FORBIDDEN_CHARACTERS.matcher(endpoint).find())
            throw new ParseException(InetEndpoint.class, endpoint, "Forbidden characters");
        final URI uri;
        try {
            uri = new URI("wg://" + endpoint);
        } catch (final URISyntaxException e) {
            throw new ParseException(InetEndpoint.class, endpoint, e);
        }
        if (uri.getPort() < 0 || uri.getPort() > 65535)
            throw new ParseException(InetEndpoint.class, endpoint, "Missing/invalid port number");
        try {
            InetAddresses.parse(uri.getHost());
            // Parsing ths host as a numeric address worked, so we don't need to do DNS lookups.
            return new InetEndpoint(uri.getHost(), true, uri.getPort());
        } catch (final ParseException ignored) {
            // Failed to parse the host as a numeric address, so it must be a DNS hostname/FQDN.
            return new InetEndpoint(uri.getHost(), false, uri.getPort());
        }
    }

    @Override
    public boolean equals(final Object obj) {
        if (!(obj instanceof InetEndpoint))
            return false;
        final InetEndpoint other = (InetEndpoint) obj;
        return host.equals(other.host) && port == other.port;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    /**
     * Generate an {@code InetEndpoint} instance with the same port and the host resolved using DNS
     * to a numeric address. If the host is already numeric, the existing instance may be returned.
     * Because this function may perform network I/O, it must not be called from the main thread.
     *
     * @return the resolved endpoint, or {@link Optional#empty()}
     */
    public Optional<InetEndpoint> getResolved() {
        if (isResolved)
            return Optional.of(this);
        synchronized (lock) {
            if (Duration.between(lastResolution, Instant.now()).toMinutes() > 1) {
                InetEndpoint txtResolved = resolveFromTxtRecord();
                if (txtResolved != null) {
                    resolved = txtResolved;
                    lastResolution = Instant.now();
                } else {
                    resolved = resolveFromDns();
                    lastResolution = Instant.now();
                }
            }
            return Optional.ofNullable(resolved);
        }
    }

    @Nullable
    private InetEndpoint resolveFromTxtRecord() {
        try {
            List<String> records = SimpleDns.lookupTxt(host).get();
            if (records != null) {
                for (String record : records) {
                    Matcher matcher = IPV4_PORT_PATTERN.matcher(record);
                    if (matcher.matches()) {
                        String ip = matcher.group(1);
                        int txtPort = Integer.parseInt(matcher.group(2));
                        return new InetEndpoint(ip, true, txtPort);
                    }
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    @Nullable
    private InetEndpoint resolveFromDns() {
        try {
            // Prefer v4 endpoints over v6 to work around DNS64 and IPv6 NAT issues.
            final InetAddress[] candidates = InetAddress.getAllByName(host);
            InetAddress address = candidates[0];
            for (final InetAddress candidate : candidates) {
                if (candidate instanceof Inet4Address) {
                    address = candidate;
                    break;
                }
            }
            return new InetEndpoint(address.getHostAddress(), true, port);
        } catch (final UnknownHostException e) {
            return null;
        }
    }

    @Override
    public int hashCode() {
        return host.hashCode() ^ port;
    }

    @Override
    public String toString() {
        final boolean isBareIpv6 = isResolved && BARE_IPV6.matcher(host).matches();
        return (isBareIpv6 ? '[' + host + ']' : host) + ':' + port;
    }
}

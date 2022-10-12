package com.yubico.yubikit.desktop;

import com.yubico.yubikit.core.Transport;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.regex.Pattern;

import javax.annotation.Nullable;

public class PcscConfiguration {
    private final EnumSet<Transport> transportFilter = EnumSet.allOf(Transport.class);
    private long pollingTimeout = 250;
    @Nullable
    private Pattern readerNameFilter = null;

    long getPollingTimeout() {
        return pollingTimeout;
    }

    boolean isInterfaceAllowed(Transport transport) {
        return transportFilter.contains(transport);
    }

    boolean filterName(String name) {
        if (readerNameFilter != null) {
            return readerNameFilter.matcher(name).find();
        }
        return true;
    }

    public PcscConfiguration pollingTimeout(long pollingTimeout) {
        this.pollingTimeout = pollingTimeout;
        return this;
    }

    public PcscConfiguration interfaceFilter(Transport... transports) {
        transportFilter.clear();
        transportFilter.addAll(Arrays.asList(transports));
        return this;
    }

    public PcscConfiguration readerNameFilter(Pattern pattern) {
        this.readerNameFilter = pattern;
        return this;
    }
}

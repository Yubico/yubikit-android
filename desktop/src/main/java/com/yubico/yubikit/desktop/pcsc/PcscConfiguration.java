/*
 * Copyright (C) 2022 Yubico.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.yubico.yubikit.desktop.pcsc;

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

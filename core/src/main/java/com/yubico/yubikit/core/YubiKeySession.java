package com.yubico.yubikit.core;

import java.io.IOException;

public interface YubiKeySession {
    Interface getInterface();

    boolean supportsConnection(Class<? extends YubiKeyConnection> connectionType);

    <T extends YubiKeyConnection> T openConnection(Class<T> connectionType) throws IOException;
}

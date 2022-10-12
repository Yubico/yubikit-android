package com.yubico.yubikit.desktop;

import com.yubico.yubikit.core.Logger;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.TerminalFactory;

public class YubiKitManager {
    private final CardTerminals terminals;
    private final AtomicBoolean running = new AtomicBoolean();
    private final Map<String, PcscDevice> sessions = new HashMap<>();

    public YubiKitManager(CardTerminals cardTerminals) {
        this.terminals = cardTerminals;
    }

    public YubiKitManager() {
        this(TerminalFactory.getDefault().terminals());
    }

    public void stop() {
        running.set(false);
    }

    /**
     * Starts listening for YubiKey device events. This method will continue to run until
     * {@link #stop} is called. The callback will be invoked in the same (single) thread which this
     * method is invoked on.
     *
     * @param configuration options which influence listening behavior
     * @param listener      the callback to invoke for sessions added/removed
     */
    public void run(PcscConfiguration configuration, PcscSessionListener listener) {
        if (!running.compareAndSet(false, true)) {
            throw new IllegalStateException("PCSC detection already running!");
        }

        while (running.get()) {
            Set<String> removed = new HashSet<>(sessions.keySet());
            try {
                for (CardTerminal terminal : terminals.list(CardTerminals.State.CARD_PRESENT)) {
                    String name = terminal.getName();
                    if (sessions.containsKey(name)) {
                        removed.remove(name);
                    } else if (configuration.filterName(name)) {
                        PcscDevice session = new PcscDevice(terminal);
                        sessions.put(name, session);
                        if (configuration.isInterfaceAllowed(session.getTransport())) {
                            Logger.d("Session started: " + name);
                            listener.onSessionReceived(session);
                        }
                    }
                }
                for (String name : removed) {
                    PcscDevice session = sessions.remove(name);
                    if (configuration.isInterfaceAllowed(session.getTransport())) {
                        Logger.d("Session ended: " + name);
                        listener.onSessionRemoved(session);
                    }
                }
                terminals.waitForChange(configuration.getPollingTimeout());
            } catch (CardException e) {
                e.printStackTrace();
            }
        }

        for (Map.Entry<String, PcscDevice> entry : sessions.entrySet()) {
            PcscDevice session = entry.getValue();
            if (configuration.isInterfaceAllowed(session.getTransport())) {
                Logger.d("Session ended: " + entry.getKey());
                listener.onSessionRemoved(session);
            }
        }
        sessions.clear();
    }
}

package com.bai.checkers;

import com.bai.util.Config;
import com.bai.util.Logging;
import java.util.Map;

/**
 * CheckerManager.
 */
public class CheckerManager {

    private static final Map<String, CheckerBase> CHECKER_MAP = Map.ofEntries(
            Map.entry("CWE134", new CWE134()),
            Map.entry("CWE190", new CWE190()),
            Map.entry("CWE367", new CWE367()),
            Map.entry("CWE426", new CWE426()),
            Map.entry("CWE467", new CWE467()),
            Map.entry("CWE676", new CWE676()),
            Map.entry("CWE78", new CWE78())
    );

    /**
     * Add all registered checkers to config.
     * @param config the config object.
     */
    public static void loadAllCheckers(Config config) {
        CHECKER_MAP.keySet().forEach(config::addChecker);
    }

    /**
     * Run all checkers specified in config.
     * @param config the config object.
     */
    public static void runCheckers(Config config) {
        for (String name : config.getCheckers()) {
            CheckerBase checker = CHECKER_MAP.get(name);
            if (checker != null) {
                Logging.info("Running checker " + checker.getCwe());
                checker.check();
            }
        }
    }

    /**
     * Get all names of all registered checkers.
     * @return a string array of checker names.
     */
    public static String[] getCheckerNames() {
        return CHECKER_MAP.keySet().toArray(new String[0]);
    }

    /**
     * Checks if the given checker name has registered.
     * @param name the checker name.
     * @return true if the checker name has registered, false otherwise.
     */
    public static boolean hasChecker(String name) {
        return CHECKER_MAP.containsKey(name);
    }

}

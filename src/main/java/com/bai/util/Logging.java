package com.bai.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.ConfigurationSource;
import org.apache.logging.log4j.core.config.xml.XmlConfiguration;

/**
 * Logging class.
 */
public class Logging {

    private static final String DEFAULT_LOGGER_NAME = "BinAbsInspector";
    private static final String CWE_LOGGER_NAME = "CWE";
    private static final String DEFAULT_CONFIG_FILE_PATH = "/log4j2_default.xml";
    private static final String DEBUG_CONFIG_FILE_PATH = "/log4j2_debug.xml";
    private static final String JSON_CONFIG_FILE_PATH = "/log4j2_json.xml";
    private static final String DEBUG_TAG = "[DEBUG] ";
    private static final String INFO_TAG = "[INFO] ";
    private static final String WARN_TAG = "[WARN] ";

    private static Logger defaultLogger;
    private static Logger cweLogger;
    private static HashMap<CWEReport, CWEReport> cweReportMap = new HashMap<>();

    /**
     * Initialize the logging module.
     * @return true if init success, false otherwise.
     */
    public static boolean init() {
        if (GlobalState.config.isGUI()) {
            return true;
        }
        String configPath = GlobalState.config.isDebug() ? DEBUG_CONFIG_FILE_PATH : DEFAULT_CONFIG_FILE_PATH;
        configPath = GlobalState.config.isOutputJson() ? JSON_CONFIG_FILE_PATH : configPath;
        InputStream in = Logging.class.getResourceAsStream(configPath);
        try {
            Configuration configuration = new XmlConfiguration(new LoggerContext(DEFAULT_LOGGER_NAME),
                    new ConfigurationSource(in));
            LoggerContext context = (LoggerContext) LogManager.getContext(true);
            context.stop();
            context.start(configuration);
            defaultLogger = context.getLogger(DEFAULT_LOGGER_NAME);
            cweLogger = context.getLogger(CWE_LOGGER_NAME);
        } catch (IOException e) {
            System.out.println("Cannot locate logging config file :" + in);
            return false;
        }
        return true;
    }

    /**
     * Get all cwe reports.
     * @return the map of all cwe reports.
     */
    public static Map<CWEReport, CWEReport> getCWEReports() {
        return cweReportMap;
    }

    /**
     * Clear all cwe reports.
     */
    public static void resetReports() {
        cweReportMap.clear();
    }

    /**
     * Generate an error log.
     * @param msg the log message.
     */
    public static void error(String msg) {
        if (GlobalState.config.isGUI()) {
            GlobalState.ghidraScript.printerr(msg + "\n");
        } else {
            defaultLogger.error(msg);
        }
    }

    /**
     * Generate a warning log.
     * @param msg the log message.
     */
    public static void warn(String msg) {
        if (GlobalState.config.isGUI()) {
            GlobalState.ghidraScript.println(WARN_TAG + msg);
        } else {
            defaultLogger.warn(msg);
        }
    }

    /**
     * Generate a info log.
     * @param msg the log message.
     */
    public static void info(String msg) {
        if (GlobalState.config.isGUI()) {
            GlobalState.ghidraScript.println(INFO_TAG + msg);
        } else {
            defaultLogger.info(msg);
        }
    }

    /**
     * Generate a debug log
     * @param msg the debug log.
     */
    public static void debug(String msg) {
        if (GlobalState.config.isGUI()) {
            if (GlobalState.config.isDebug()) {
                GlobalState.ghidraScript.println(DEBUG_TAG + msg);
            }
        } else {
            defaultLogger.debug(msg);
        }
    }

    /**
     * Emit a cwe report.
     * @param cweReport the cwe report.
     */
    public static void report(CWEReport cweReport) {
        if (!cweReportMap.containsKey(cweReport)) {
            if (GlobalState.config.isGUI()) {
                GlobalState.ghidraScript.println(WARN_TAG + cweReport.toString());
            } else {
                cweLogger.warn(cweReport);
            }
            cweReportMap.put(cweReport, cweReport);
        } else {
            if (GlobalState.config.isGUI()) {
                if (GlobalState.config.isDebug()) {
                    GlobalState.ghidraScript.println("Already reported! " + cweReport.toString());
                }
            } else {
                cweLogger.debug("Already reported! " + cweReport);
            }
        }
    }
}

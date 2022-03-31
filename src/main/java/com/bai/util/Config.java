package com.bai.util;

import static java.lang.Integer.parseInt;

import com.bai.checkers.CheckerManager;
import ghidra.util.exception.InvalidInputException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 * Configuration class.
 */
public class Config {

    /**
     * The config parser for headless mode arguments.
     */
    public static class HeadlessParser {

        private static boolean checkArgument(String optionName, String[] args, int argi)
                throws InvalidInputException {
            // everything after this requires an argument
            if (!optionName.equalsIgnoreCase(args[argi])) {
                return false;
            }
            if (argi + 1 == args.length) {
                throw new InvalidInputException(optionName + " requires an argument");
            }
            return true;
        }

        private static String[] getSubArguments(String[] args, int argi) {
            List<String> subArgs = new LinkedList<>();
            int i = argi + 1;
            while (i < args.length && !args[i].startsWith("-")) {
                subArgs.add(args[i++]);
            }
            return subArgs.toArray(new String[0]);
        }

        private static void usage() {
            System.out.println("Usage: ");
            System.out.println(
                    "analyzeHeadless <project_location> <project_name[/folder_path]> -import <file>");
            System.out.println("-postScript BinAbsInspector.java \"@@<script parameters>\"");
            System.out.println("where <script parameters> in following format: ");
            System.out.println("        [-K <kElement>]");
            System.out.println("        [-callStringK <callStringMaxLen>]");
            System.out.println("        [-Z3Timeout <timeout>]");
            System.out.println("        [-timeout <timeout>]");
            System.out.println("        [-entry <address>]");
            System.out.println("        [-externalMap <file>]");
            System.out.println("        [-json]");
            System.out.println("        [-disableZ3]");
            System.out.println("        [-all]");
            System.out.println("        [-debug]");
            System.out.println("        [-check \"<cweNo1>[;<cweNo2>...]\"]");
        }

        public static Config parseConfig(String fullArgs) {
            Config config = new Config();
            if (fullArgs.isEmpty()) {
                return config;
            }
            if (fullArgs.getBytes()[0] != '@' && fullArgs.getBytes()[1] != '@') {
                System.out.println("Wrong parameters: <script parameters> should start with '@@'");
                usage();
                System.exit(-1);
            }
            try {
                String[] args = fullArgs.substring(2).split(" ");
                for (int argi = 0; argi < args.length; argi++) {
                    String arg = args[argi];
                    if (checkArgument("-K", args, argi)) {
                        config.setK(parseInt(args[++argi]));
                    } else if (checkArgument("-callStringK", args, argi)) {
                        config.setCallStringK(parseInt(args[++argi]));
                    } else if (checkArgument("-Z3Timeout", args, argi)) {
                        config.setZ3TimeOut(parseInt(args[++argi]));
                    } else if (checkArgument("-timeout", args, argi)) {
                        config.setTimeout(parseInt(args[++argi]));
                    } else if (checkArgument("-entry", args, argi)) {
                        config.setEntryAddress(args[++argi]);
                    } else if (checkArgument("-externalMap", args, argi)) {
                        config.setExternalMapPath(args[++argi]);
                    } else if (arg.equalsIgnoreCase("-json")) {
                        config.setOutputJson(true);
                    } else if (arg.equalsIgnoreCase("-disableZ3")) {
                        config.setEnableZ3(false);
                    } else if (arg.equalsIgnoreCase("-all")) {
                        CheckerManager.loadAllCheckers(config);
                    } else if (arg.equalsIgnoreCase("-debug")) {
                        config.setDebug(true);
                    } else if (checkArgument("-check", args, argi)) {
                        String[] checkers = getSubArguments(args, argi);
                        Arrays.stream(checkers)
                                .filter(CheckerManager::hasChecker)
                                .forEach(config::addChecker);
                        argi += checkers.length;
                    }
                }
            } catch (InvalidInputException | IllegalArgumentException e) {
                System.out.println("Fail to parse config from: \"" + fullArgs + "\"");
                usage();
                System.exit(-1);
            }
            System.out.println("Loaded config: " + config);
            return config;
        }
    }

    private static final int DEFAULT_Z3_TIMEOUT = 1000; // unit in millisecond

    private static final int DEFAULT_CALLSTRING_K = 3;

    private static final int DEFAULT_K = 50;

    private static final int DEFAULT_TIMEOUT = -1; // unit in second, no timeout by default

    private int z3TimeOut;

    private boolean isDebug;

    private boolean isOutputJson;

    @SuppressWarnings("checkstyle:MemberName")
    private int K;

    private int callStringK;

    private List<String> checkers = new ArrayList<>();

    private String entryAddress;

    private int timeout;

    private boolean isEnableZ3;

    private String externalMapPath;

    private boolean isGUI;

    // for tactic tuning, see:
    // http://www.cs.tau.ac.il/~msagiv/courses/asv/z3py/strategies-examples.htm
    private List<String> z3Tactics = new ArrayList<>();

    public Config() {
        // default config
        this.callStringK = DEFAULT_CALLSTRING_K;
        this.K = DEFAULT_K;
        this.isDebug = false;
        this.isOutputJson = false;
        this.z3TimeOut = DEFAULT_Z3_TIMEOUT; // ms
        this.timeout = DEFAULT_TIMEOUT;
        this.entryAddress = null;
        this.isEnableZ3 = true;
        this.externalMapPath = null;
    }

    /**
     * Get the timeout (millisecond) for z3 constraint solving.
     * @return the timeout (millisecond).
     */
    public int getZ3TimeOut() {
        return z3TimeOut;
    }

    /**
     * Set the timeout (millisecond) for z3 constraint solving.
     * @param z3TimeOut the timeout (millisecond).
     */
    public void setZ3TimeOut(int z3TimeOut) {
        this.z3TimeOut = z3TimeOut;
    }

    /**
     * Get a list of z3 tactic names.
     * @return the list of z3 tactic names.
     */
    public List<String> getZ3Tactics() {
        return z3Tactics;
    }

    /**
     * Checks if in debug config.
     * @return true if in debug config, false otherwise.
     */
    public boolean isDebug() {
        return isDebug;
    }

    /**
     * Set debug config.
     * @param debug in debug config or not.
     */
    public void setDebug(boolean debug) {
        this.isDebug = debug;
    }

    /**
     * Check if using json output.
     * @return ture if using json output, false otherwise.
     */
    public boolean isOutputJson() {
        return isOutputJson;
    }

    /**
     * Set json output
     * @param isOutputJson use json format output or not.
     */
    public void setOutputJson(boolean isOutputJson) {
        this.isOutputJson = isOutputJson;
    }

    /**
     * Get the K parameter.
     * @return the K parameter.
     */
    public int getK() {
        return K;
    }

    /**
     * Set the K parameter.
     * @param k the K parameter.
     */
    public void setK(int k) {
        K = k;
    }

    /**
     * Get the call string max length: K.
     * @return the call string k.
     */
    public int getCallStringK() {
        return callStringK;
    }

    /**
     * Set the call string max length: K.
     * @param callStringK the call string k.
     */
    public void setCallStringK(int callStringK) {
        this.callStringK = callStringK;
    }

    /**
     * Get a list of checker names to run.
     * @return a list of checker names.
     */
    public List<String> getCheckers() {
        return checkers;
    }

    /**
     * Add a checker to run.
     * @param name the checker name.
     */
    public void addChecker(String name) {
        checkers.add(name);
    }

    /**
     * Clear all checkers config.
     */
    public void clearCheckers() {
        checkers.clear();
    }

    /**
     * Get the analysis timeout (in second).
     * @return the analysis timout (in second).
     */
    public int getTimeout() {
        return timeout;
    }

    /**
     * Set the analysis timeout (in second).
     * @param timeout the analysis timout (in second).
     */
    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    /**
     * Get the entry address string.
     * @return the entry address string.
     */
    public String getEntryAddress() {
        return entryAddress;
    }

    /**
     * Set the entry address, accept format of decimal or hexadecimal.
     * @param entryAddress the entry address.
     */
    public void setEntryAddress(String entryAddress) {
        this.entryAddress = entryAddress;
    }

    /**
     * Checks if enable z3 constraint solving.
     * @return true if enabled, false otherwise.
     */
    public boolean isEnableZ3() {
        return isEnableZ3;
    }

    /**
     * Enable z3 config.
     * @param enableZ3 enable or not.
     */
    public void setEnableZ3(boolean enableZ3) {
        isEnableZ3 = enableZ3;
    }

    /**
     *  Get the path of external map config json file.
     * @return the file path.
     */
    public String getExternalMapPath() {
        return externalMapPath;
    }

    /**
     * Set the path of external map config json file.
     * @param externalMapPath the file path.
     */
    public void setExternalMapPath(String externalMapPath) {
        this.externalMapPath = externalMapPath;
    }

    /**
     * Checks if running in GUI mode.
     * @return true if in GUI mode, false otherwise.
     */
    public boolean isGUI() {
        return isGUI;
    }

    /**
     * @hidden
     * @param isGUI
     */
    public void setGUI(boolean isGUI) {
        this.isGUI = isGUI;
    }

    @Override
    public String toString() {
        return "Config{"
                + "z3TimeOut=" + z3TimeOut
                + ", isDebug=" + isDebug
                + ", isOutputJson=" + isOutputJson
                + ", K=" + K
                + ", callStringK=" + callStringK
                + ", checkers=" + checkers
                + ", entryAddress='" + entryAddress + '\''
                + ", timeout=" + timeout
                + ", isEnableZ3=" + isEnableZ3
                + ", z3Tactics=" + z3Tactics
                + ", externalMapPath=" + externalMapPath
                + '}';
    }
}

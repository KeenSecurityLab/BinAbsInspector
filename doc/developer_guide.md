# Developer Guide
## Development Environment Setup
We use Gradle to manage dependencies and test tasks. You can use IntelliJ IDEA or Eclipse for development.
+ Install Java
	+ Tested version jdk-11.0.12
+ Install Gradle 7.0+
	+ Tested version 7.3.3
+ Install Ghidra From [release page](https://github.com/NationalSecurityAgency/ghidra/releases)
	+ Tested version 10.1.2
+ Setup environemnt variable `GHIDRA_INSTALL_DIR` to your Ghidra install path, here is references for [Windows](https://docs.oracle.com/en/database/oracle/machine-learning/oml4r/1.5.1/oread/creating-and-modifying-environment-variables-on-windows.html#GUID-DD6F9982-60D5-48F6-8270-A27EC53807D0) , [Linux](https://linuxize.com/post/how-to-set-and-list-environment-variables-in-linux/), [macOS](https://phoenixnap.com/kb/set-environment-variable-mac).
+ Install Z3
	+ Tested version 4.8.15
	+ We've including a java binding library for 4.8.15 at ./lib/com.microsoft.z3.jar, you need to install pre-built z3 library of same version from https://github.com/Z3Prover/z3/releases/tag/z3-4.8.15.
	+ Or you can build and install a fresh Z3 library according to the steps from: [Z3 Readme](https://github.com/Z3Prover/z3), and copy the generated java binding package (com.microsoft.z3.jar) to ./lib
### For Intellj IDEA
+ It is recommended to use intellij-ghidra plugin for testing and debugging: [intellj-ghidra](https://github.com/garyttierney/intellij-ghidra)
+ git clone our repo
+ In Intellj File Menu, select `New -> Project from existing sources`, select the project directory and choose `Import project from exteranl model -> gradle`, then click `Finish`.
+ If everything works well, the IDE will resovle all dependencies. In File Menu, select `Project structure->Facets`, click the `+` button and select `Ghidra` and the project root directory, then click `OK`, Fill the `Path to Ghidra installation` text field and click `OK`.
+ Click `Add Configuration...` on top right, then Click `Add new...` and select `Ghidra Lanuncher`, Fill configuation name. If you want to run in headless mode, you can select the `use headless` checkbox and fill the `args` according to user guide. At last, click `OK` button.
+ Now you can click the `run` or `debug` button on top right and run Ghidra with developing script loaded.

### For Eclipse
reference: https://github.com/googleinterns/ghidra-nsis-extension
+ Install Ghidra Eclipse extension, following instructions: https://ghidra-sre.org/InstallationGuide.html#Extensions
+ git clone the repo
+ In Eclipse's File menu, select `New->Java Project`
+ Deselect `Use default location` and navigate to the project folder
+ Press `Next`
+ Deselect `Create module-info.jva file`
+ Press `Finish`
    + There will be build error
+ In the `GhidraDev` menu of Eclipse, use the `Link Ghidra...` and enter the path to the Ghidra binary install location.
    + Select the Java project just created
    + If there is java conflict probably best to keep the current Java by pressing `Cancel`
    + Build errors should be resoved
+ Add the jar file under `./lib` to the build path in Eclipse to import those dependencies.
+ You can test that everything is working in your project by selecting the "Run" menu, then "Run As " and "Ghidra".

## Checker Development
You can write your own checkers for other kinds of vulnerabilities. This page will show you how to do this via an example.

### Step1: Design checker logic
Assume that we want to write a new checker for [CWE134](https://cwe.mitre.org/data/definitions/134.html) (Use of Externally-Controlled Format String), we need to answer the following questions:
1. Which program point should the checker examine?
2. What properties should a bug-free program have?
To answer this question, we first look at a simple example program.
```c
#include <stdlib.h>
#include <stdio.h>

void foo(char * ptr) {
    printf(ptr);
}

int main() {
    char * ptr = (char *) malloc(0x10);
    scanf("%16s", ptr);
    foo("test");
    foo(ptr);
    free(ptr);
}

```
This program calls the `foo` function twice; the first time uses a constant string argument `test`, which does not pose any security risk; the second time uses an argument passed from external input, which might result in an exploitable format string vulnerability. We can suggest a simple strategy for finding similar issues based on the observation: we can examine whether the first argument for the `printf` function points to writable memory.
So the answers to previous questions are:
1. We should locate every program point that calls `printf` in the program.
2. We should check the first argument at the call site, if it points to a writable memory address, we can emit a warning.
### Step2: Implement checker logic
All checkers are located at `src.main.java.ghidra.bai.checkers`, and it should be subclasses of `CheckerBase`. First, we create a new class for the checker like:
```java
public class CWE134 extends CheckerBase {
    public CWE134() {
        super("CWE134", "0.1");
        description = "Use of Externally-Controlled Format String: The software uses a function that "
        + "accepts a format string as an argument, but the format string originates from an external source.";
    }
    
    @Override
    public boolean check() {
        //implement checker logic here.
    }
}
```
We need to fill metadata in the new checker class's constructor and implement the logic in `check` method.
As we've mentioned before, we first need to locate every call site to `printf`, with the help of Ghidra API, we can make a query like:
```java
public boolean check() {
boolean hasWarning = false;
    try {
        SymbolTable symbolTable = GlobalState.currentProgram.getSymbolTable();
        if (symbolTable == null) {
            Logging.error("Empty symbols table");
            return false;
        }
        SymbolIterator iterator = symbolTable.getSymbolIterator();
        while (iterator.hasNext()) {
            Symbol currentSymbol = iterator.next();
            if (!currentSymbol.getName().equals("printf")) {
                continue;
            }
            Logging.debug("Processing symbol \"" + currentSymbol.getName() + "()\"");
            for (Reference ref : currentSymbol.getReferences()) {
                if (ref.getReferenceType() == RefType.THUNK) {
                    break; // skip THUNK function.
                }
                Address toAddress = ref.getToAddress();
                Address fromAddress = ref.getFromAddress();
                Function callee = GlobalState.flatAPI.getFunctionAt(toAddress);
                Function caller = GlobalState.flatAPI.getFunctionContaining(fromAddress);
                if (callee == null || caller == null) {
                    continue;
                }
                Logging.debug(fromAddress + " -> " + toAddress + " " + callee.getName());
            }
        }
    } catch (Exception exception) {
        exception.printStackTrace();
    }
    return hasWarning;    
}
```
On line 4, we get `SymbolTable` with `GlobalState.currentProgram`, noted that [GlobalState.currentProgram](https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html) and [GlobalState.flatAPI](https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html) are two main interfaces to invoke Ghidra's API. Remeber to use `flatAPI` whenever it is possible, as it is immutable among various Ghidra versions. From line 10-14, we iterate over the symbol table to find every symbol named `printf`, and then find their references. Because we don't care about the thunk call sites, we can skip those references on line 17-19. We can get the call site address `fromAddress`, callee function entry address `toAddress`.
Now that we've gatheredhe related addresses, we can add the following code to line 28.
```java
for (Context context : Context.getContext(caller)) {
    AbsEnv absEnv = context.getAbsEnvIn().get(fromAddress);
    if (absEnv == null) {
        continue;
    }
    hasWarning |= checkFunctionParameters(context, absEnv, callee, fromAddress);
}
```
A for-loop is used to query every AbsEnv that corresponded to the printf call site from the analysis result. We first get every context object of the caller functions with `Context.getContext()`, then we query the `AbsEnv` with the call site addresses and pass them to `checkFunctionParameters()` function.
```java
private boolean checkFunctionParameters(Context context, AbsEnv absEnv, Function callee, Address address) {
    String name = callee.getName();
    int paramIndex = 0;
    Logging.debug("Processing argument " + paramIndex + " at " + name + "()");
    boolean result = false;
    KSet argKSet = getParamKSet(callee, paramIndex, absEnv);
    if (!argKSet.isNormal()) {
        return false;
    }
    Logging.debug("KSet for argument: " + argKSet);
    for (AbsVal argAbsVal : argKSet) {
        if (!isAbsValWritable(argAbsVal)) {
            Logging.debug("Argument is not writeable: " + argAbsVal);
            continue;
        }
        Logging.debug("Argument is writeable: " + argAbsVal);
        // We might have found a use of the writeable region as the format string
        CWEReport report = getNewReport("Potentially externally controlled format string \""
                + name + "()\" call").setAddress(address);
        Logging.report(report);
        result = true;
    }
    return result;
}
```
The purpose of `checkFunctionParameters` is examining whether the first argument of queried AbsEnv contains a pointer to writable memory addresses. In line 6, we get the KSet that corresponds to the first argument. We should skip `TOP` and `BOT` KSet, so we add a quick return on line 7-9. From line 11 to 22, we iterate over every AbsVal in the KSet, and pass them to the `isAbsValWritable` function, if it fails the check, then we emit a cwe report.
It is also straightforward with the `isAbsValWritable` function. We consider pointers to heap or local (stack) regions always writable. For pointers to the Global region, we determine its property with Ghidra API.
```java
private static boolean isAbsValWritable(AbsVal ptr) {
    RegionBase region = ptr.getRegion();
    if (region.isLocal() || region.isHeap()) {
        return true;
    }
    if (region.isGlobal() && !ptr.isBigVal()) {
        Address address = GlobalState.flatAPI.toAddr(ptr.getValue());
        MemoryBlock memoryBlock = GlobalState.flatAPI.getMemoryBlock(address);
        if (memoryBlock == null) {
            return false;
        }
        return memoryBlock.isWrite();
    }
    return false;
}
```
### Step 3: Register the new checker
The final step is to register the newly created checker to the checker manager. We need to add a new entry at `CheckerManager.CHECKER_MAP`.
```java
public static final Map<String, CheckerBase> CHECKER_MAP = Map.ofEntries(
    Map.entry("CWE134", new CWE134()),
    ...
);
```
### Step 4: Run the checker
Now a new checker is born, you can try to run it with following argument in `intellj-ghidra`:
```
<projectPath> <projectName> -import <binary> -scriptPath <scriptPath> -postScript BinAbsInspector.java "@@-check CWE134"
```





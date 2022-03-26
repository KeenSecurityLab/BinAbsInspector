# What is  BinAbsInspector?

BinAbsInspector is a static analyzer for automated reverse engineering and scanning vulnerabilities in binaries. It is based on abstract interpretation with the support from Ghidra. It works on Ghidra's Pcode instead of assembly. Currently it supports binaries on x86,x64, armv7 and aarch64.

# Installation
+ Install JDK 11 64-bit
+ Download Ghidra from [release page](https://github.com/NationalSecurityAgency/ghidra/releases/),
+ Setup environment variable `GHIDRA_INSTALL_DIR` with Ghidra installation path
+ Install [Z3](https://github.com/Z3Prover/z3/blob/master/README-CMake.md) and copy  `com.microsoft.z3-VERSION.jar` to `./lib`
+ Build BinAbsInspector with `gradle buildExtension`
+ The output zip  file located at `./dist`, [install it](https://ghidra-sre.org/InstallationGuide.html#Extensions).

# Usage
+ Run headless mode in terminal
```
$GHIDRA_INSTALL_DIR/support/analyzeHeadless <projectPath> <projectName> -import <file> -scriptPath <scriptPath> -postScript BinAbsInspector "@@<script parameters>"
```
&lt;projectPath&gt;   --   Ghidra projectPath.  
&lt;projectName&gt;   --   Ghidra project name.  
&lt;scriptPath&gt;    --   BinAbsInspector script path.

+ Run BinAbsInspector in Ghidra GUI

First import the target binary into Ghidra and analyze it.
Then open Ghidra Script Manager and run BinAbsInspector. You can also setup configuration parameters.

You can see the CWE report from the console.

+ Run with Docker

```shell
docker build . -t BinAbsInspector //setup a docker image
docker run -v $(pwd):/data/workspace BinAbsInspector "@@<script parameters>" -import <file>
```

&lt;script parameters&gt; are  in following formats:

| script parameters                         | Description                                |
| ----------------------------------------- | --------------------------------------- |
| \[-K \<kElement\>\]                       | KSet size                           |
| \[-callStringK \<callStringMaxLen>\]      | Call string maximum length                   |
| \[-Z3Timeout\] <\timeout\>                | Z3 timeout                      |
| \[-timeout\] \<timeout\>                  | Analysis timeout                |
| \[-entry\] \<address\>                    | Entry address                       |
| \[-externalMap\] \<file\>                 | External function model file                |
| \[-json\]                                 | Output Json file                 |
| \[-disableZ3\]                            | Disable Z3                    |
| \[-all\]                                  | Enable all checkers (by default)          |
| \[-debug\]                                | Enable debugging log output |
| \[-check "\<cweNo1\>\[;\<cweNo2\>...\]"\] | Enable specific checkers                            |

# Implemented Checkers
So far BinAbsInspector supports following checkers:

+ CWE78 (OS Command Injection)
+ CWE119 (Buffer Overflow (generic case))
+ CWE125 (Buffer Overflow (Out-of-bounds Read))
+ CWE134 (Use of Externally-Controlled Format string)
+ CWE190 (Integer overflow or wraparound)
+ CWE367 (TOCTOU)
+ CWE415 (Double free)
+ CWE416 (Use After Free)
+ CWE426 (Untrusted Search Path)
+ CWE467 (Use of sizeof() on a pointer type)
+ CWE476 (NULL Pointer Dereference)
+ CWE676 (Use of Potentially Dangerous Function)
+ CWE787 (Buffer Overflow (Out-of-bounds Write))

# Developing
You can add your own checkers based on BinAbsInspector analysis engine.
```
├── main
│   ├── java
│   │   └── com
│   │       └── bai
│   │           ├── checkers                       checker implementatiom
│   │           ├── env
│   │           │   ├── funcs                      function modeling
│   │           │   │   ├── externalfuncs          external function modeling
│   │           │   │   └── stdfuncs               cpp std modeling
│   │           │   └── region                     memory modeling
│   │           ├── solver                         analyze core and grpah module
│   │           └── util                           utilities
│   └── resources
└── test
```
# Acknowledgement
We employ [Ghidra](https://ghidra-sre.org/) as our foundation and frequently leverage [JImmutable Collections](http://brianburton.github.io/java-immutable-collections/) for better performance.  
Here we would like to thank them for their great help!

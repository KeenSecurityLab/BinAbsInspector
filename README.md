# What is  BinAbsInspector?

BinAbsInspector (Binary Abstract Inspector) is a static analyzer for automated reverse engineering and scanning vulnerabilities in binaries. It is based on abstract interpretation with the support from Ghidra. It works on Ghidra's Pcode instead of assembly. Currently it supports binaries on x86,x64, armv7 and aarch64.

# Installation
+ Install Ghidra according to [Ghidra's documentation](https://github.com/NationalSecurityAgency/ghidra#install)
+ Install [Z3](https://github.com/Z3Prover/z3) (tested version: 4.8.15)
  + For Windows, download a pre-built package from [here](https://github.com/Z3Prover/z3/releases), extract the zip file and add a PATH environment variable pointing to `z3-${version}-win/bin`
  + For Linux, install with package manager is NOT recommended, there are two options:
    1. You can download suitable pre-build package from [here](https://github.com/Z3Prover/z3/releases), extract the zip file and copy `z3-${version}-win/bin/*.so` to `/usr/local/lib/`
    2. or you can build and install z3 according to [Building Z3 using make and GCC/Clang](https://github.com/Z3Prover/z3#building-z3-using-make-and-gccclang)
  + For MacOS, it is similar to Linux.
+ Download the extension zip file from [release page](https://github.com/zyq8709/BinAbsInspector/releases/tag/release)
+ Install the extension according to [Ghidra Extension Notes](https://ghidra-sre.org/InstallationGuide.html#GhidraExtensionNotes)

# Building
Build the extension by your self, if you want to develop a new feature, please refer to [developing guide](./doc/developer_guide.md).
+ Install Ghidra and Z3
+ Install [Gradle 7.x](https://gradle.org/releases/) (tested version: 7.4)
+ Pull the repository
+ Run `gradle buildExtension` under repository root
+ The extension will be generated at `dist/${GhidraVersion}_${date}_BinAbsInspector.zip` 

# Usage
You can run BinAbsInspector in headless mode, GUI mode, or with docker.

+ With Ghidra headless mode.
```
$GHIDRA_INSTALL_DIR/support/analyzeHeadless <projectPath> <projectName> -import <file> -postScript BinAbsInspector "@@<scriptParams>"
```
`<projectPath>`   --   Ghidra project path.  
`<projectName>`   --   Ghidra project name.  
`<scriptParams>`  --   The argument for our analyzer, provides following options:

| Parameter                                 | Description                           |
| ----------------------------------------- | --------------------------------------|
| `[-K <kElement>]`                         | KSet size limit [K](./doc/technical_details.md#KSet)             |
| `[-callStringK <callStringMaxLen>]`       | Call string maximum length [K](./doc/technical_details.md#Context)|
| `[-Z3Timeout <timeout>]`                  | Z3 timeout                            |
| `[-timeout <timeout>]`                    | Analysis timeout                      |
| `[-entry <address>]`                      | Entry address                         |
| `[-externalMap <file>]`                   | External function model config        |
| `[-json]`                                 | Output in json format                 |
| `[-disableZ3]`                            | Disable Z3                            |
| `[-all]`                                  | Enable all checkers (by default)      |
| `[-debug]`                                | Enable debugging log output           |
| `[-check "<cweNo1>[;<cweNo2>...]"]`       | Enable specific checkers              |

+ With Ghidra GUI
  1. Run Ghidra and import the target binary into a project
  2. Analyze the binary with default settings
  3. When the analysis is done, open `Window -> Script Manager` and find `BinAbsInspector.java`
  4. Double-click on `BinAbsInspector.java` entry, set the parameters in configuration window and click OK
  5. When the analysis is done, you can see the CWE reports in console window, double-click the addresses from the report can jump to corresponding address

+ With Docker

```shell
docker build . -t BinAbsInspector
docker run -v $(pwd):/data/workspace BinAbsInspector "@@<script parameters>" -import <file>
```

# Implemented Checkers
So far BinAbsInspector supports following checkers:

+ [CWE78](https://cwe.mitre.org/data/definitions/78.html)  (OS Command Injection)
+ [CWE119](https://cwe.mitre.org/data/definitions/119.html) (Buffer Overflow (generic case))
+ [CWE125](https://cwe.mitre.org/data/definitions/125.html) (Buffer Overflow (Out-of-bounds Read))
+ [CWE134](https://cwe.mitre.org/data/definitions/134.html) (Use of Externally-Controlled Format string)
+ [CWE190](https://cwe.mitre.org/data/definitions/190.html) (Integer overflow or wraparound)
+ [CWE367](https://cwe.mitre.org/data/definitions/367.html) (Time-of-check Time-of-use (TOCTOU))
+ [CWE415](https://cwe.mitre.org/data/definitions/415.html) (Double free)
+ [CWE416](https://cwe.mitre.org/data/definitions/416.html) (Use After Free)
+ [CWE426](https://cwe.mitre.org/data/definitions/426.html) (Untrusted Search Path)
+ [CWE467](https://cwe.mitre.org/data/definitions/467.html) (Use of sizeof() on a pointer type)
+ [CWE476](https://cwe.mitre.org/data/definitions/476.htmll) (NULL Pointer Dereference)
+ [CWE676](https://cwe.mitre.org/data/definitions/676.html) (Use of Potentially Dangerous Function)
+ [CWE787](https://cwe.mitre.org/data/definitions/787.html) (Buffer Overflow (Out-of-bounds Write))

# Developing
The structure of this project is as follows, please refer to [technical details](./doc/technical_details.md) for more details.
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
You can also build the javadoc with `gradle javadoc`, the API documentation will be generated in `./build/docs/javadoc`.

# Acknowledgement
We employ [Ghidra](https://ghidra-sre.org/) as our foundation and frequently leverage [JImmutable Collections](http://brianburton.github.io/java-immutable-collections/) for better performance.  
Here we would like to thank them for their great help!

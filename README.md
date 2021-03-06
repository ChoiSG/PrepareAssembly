# Invoke-PrepareAssembly

Powershell script that git-clones, compiles, obfuscates, donuts, and encrypts .NET assemblies. This project is pretty much a (scuffed and worse) powershell port of OffensivePipeline.

You probably want to use an actual CI/CD pipeline instead of this half-baked powershell script. At most this would be useful for homelabs and personal use.

For a real CI/CD pipeline, consider using something with Azure like [@Flangvik](https://twitter.com/Flangvik)'s [SharpCollection](https://github.com/Flangvik/SharpCollection)

**All credits goes to :** 
- [@domchell](https://twitter.com/domchell?lang=en) and his mind-blowing CovertToolsmith presentation (galaxy brain)
- [@Aetsu's Offensive Pipeline](https://github.com/Aetsu/OffensivePipeline). This project is pretty much a (scuffed and worse) powershell port of OffensivePipeline.
- [@FuzzySec](https://twitter.com/FuzzySec)'s [Discerning Finch](https://github.com/FuzzySecurity/Sharp-Suite/blob/master/DiscerningFinch) - For environmental keying and decrypting - inspired to add encrytion 

## Demo 

![Invoke-PrepareAssembly](/image/invoke_prepareAssembly_demo2.gif)

## Requirements 
(From OffensivePipeline README) 

1. Build Tools for Visual Studio 2019: https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=BuildTools&rel=16
-  Install .NET Desktop build tools 

2. `nuget.exe, Confuser.CLI.exe, git.exe, donut.exe` in your `PATH` environment. The script will download/recommend these binaries, but you have to manually put these in your PATH. 

3. [.NET 3.5.1](https://www.microsoft.com/en-us/download/details.aspx?id=22) for some tools

4. Turn off Windows Defender you dummy!

## Usage 

0. Check all the requirements 

1.  Modify the tools.json's output directory 
```
{
    "outDir": "c:\\dev\\testo\\",
    "tools": [
    . . .
```

2. Start a powershell console with execution policy bypassed, and have fun!
```
powershell -exec bypass 
. ./Invoke-PrepareAssembly
```

## Beaware 
- Currently "arch" is broken. Suggest just keeping it as `Any CPU`. If you specifically want x64 or x86, change it inside Visual studio. 
Need to research how to do this programmatically, tbd.  

**JSON file mode - RECOMMENDED**
```
# All switches at the same time
Invoke-PrepareAssembly -jsonfile ./tools.json -gitclone -compile -obfuscate 
Invoke-PrepareAssembly -jsonfile ./tools.json -compile -obfuscate

# One switch at a time  
Invoke-PrepareAssembly -jsonfile ./tools.json -gitclone 
Invoke-PrepareAssembly -jsonfile ./tools.json -compile 
Invoke-PrepareAssembly -jsonfile ./tools.json -obfuscate
Invoke-PrepareAssembly -jsonfile ./tools.json -encrypt -key "single key encrypting all tools ohnononono"

# Only specific tool - Ex. Seatbelt
Invoke-PrepareAssembly -jsonfile ./tools.json -toolname SeatBelt -gitclone -compile -obfuscate -encrypt -key "encryptmeplease"
Invoke-PrepareAssembly -jsonfile ./tools.json -toolname SeatBelt -compile -obfuscate
```

**Single file mode - Currently NOT implemented, half broken.**
```
Invoke-PrepareAssembly -gitlink <git> -gitclone 

Invoke-PrepareAssembly -slnPath <path_to_sln_file> -outDir <output_directory> -compile 

Invoke-PrepareAssembly -inFile <path_to_assembly> -outDir <output_directory> -obfuscate 

Invoke-PrepareAssembly -inFile <path_to_assembly> -outDir <output_directory> -encrypt -key "Hello World"

Invoke-PrepareAssembly -infile <path_to_assembly> -donut 

Invoke-PrepareAssembly -infile <path_to_assembly> -donut -donutArgs <donut.exe_arguments>
```

## Switches and Flags for Single File Mode
- TBH this is half implemented half broken, suggest using the jsonFile mode.

| Switches   | Mandatory Flags            | Optional Flags                     |
|------------|----------------------------|------------------------------------|
| -gitclone  | -gitLink, -outDir          | N/A                                |
| -compile   | -slnPath, -outDir          | -arch, -outputType, -dotnetVersion |
| -obfuscate | -inFile, -slnPath, -outDir | -confuserConfig, -level            |
| -encrypt   | -key                       |                                    |
| -donut     | -inFile                    | -donutArgs                         |

## Modifying ConfuserEx configuration 
- Configure the config in the source code (for now)
```
[Parameter(Mandatory=$false, HelpMessage='ConfuserEx configuration XML file path. If not provided, use a default one.')]
[string] $confuserConfig = 
@"
<project outputDir="{{OUTPUT_DIR}}" baseDir="{{BASE_DIR}}" xmlns="http://www.google.com">
    <packer id="compressor" />  
    <rule pattern="true" preset="{{LEVEL}}" inherit="false">
        <protection id="anti ildasm" />
        <protection id="anti debug" action="remove" /> <!-- this breaks Assembly.Load. Maybe just use donut?  -->
        <protection id="anti dump" />
        <protection id="anti tamper" action="remove" /> <!-- this breaks Assembly.Load. Maybe just use donut?  -->
        <protection id="invalid metadata" />
        <protection id="resources" />
        <protection id="constants" />
        <protection id="ctrl flow" />
        <protection id="rename" action="remove" /> <!-- This just killed seatbelt for some reason --> 
    </rule>
    <module path="{{MODULE_PATH}}" />
    <!-- CopyReferences will add more modules and close off the </project> element  -->
"@,
```

## Why create a worse version of OffensivePipeline?
I am a wheel re-inventing addict and I wanted to practice writing powershell scripts.

## DecryptTest 
- Simple C# binary that will load or decrypt+load assembly. Use for sanity check after obfuscating and encrypting through `Invoke-PrepareAssembly`.

```
PS> .\decryptTest.exe

ERROR(S):
  Required option 'f, file' is missing.

  -f, --file          Required. File to load and execute

  -k, --key           Key for decrypting. Automatically AES256 decrypt, load, and execute

  -p, --parameters    Optional parameter when executing the assembly

  --help              Display this help screen.

  --version           Display version information.
```

```
.\decryptTest.exe
.\decryptTest.exe -f <confused/compiled Assembly>
.\decryptTest.exe -f <confused/compiled Assembly> -p <parameter>
.\decryptTest.exe -f <confused/compiled Assembly> -k "decryptKey"
.\decryptTest.exe -f <confused/compiled Assembly> -k "decryptKey" -p <parameter>

ex. 
.\decryptTest.exe -f C:\dev\test3\Confused\Rubeus_49an72dz.exe 
.\decryptTest.exe -f C:\dev\test3\Confused\Rubeus_49an72dz.exe -p triage
.\decryptTest.exe -f C:\dev\test3\Confused\Rubeus_49an72dz.exe.aes -k "testooo"
.\decryptTest.exe -f C:\dev\test3\Confused\Rubeus_49an72dz.exe.aes -k "testooo" -p "triage"
```

- Couldn't figure out a way to input tac/dash/hyphen into parameter. 
    - ex) `.\decryptTest.exe -f <seatbelt.exe> -p "-group=user"` won't work. 
    I did some research and found `enableDashDash` for commandlineparser, but the struggle was too real. 
    Skipping this for now. 

## TODOs 
Implement and fix donut 

Add confuserEx config to `tools.json` instead?

Support base64 output for compile, obfuscate, encrypt 

Support @rastamouse's dnlib adding assembly to resources to another assembly?
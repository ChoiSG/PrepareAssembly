# Invoke-PrepareAssembly

Powershell script that clones, compiles, obfuscates, donuts, and encrypts .NET assemblies. This project is pretty much a (scuffed and worse) powershell port of OffensivePipeline.

You probably want to use an actual CI/CD pipeline instead of this half-baked powershell script. At most this would be useful for homelabs and personal use.

**All credits goes to :** 
- [@domchell](https://twitter.com/domchell?lang=en) and his mind-blowing CovertToolsmith presentation (galaxy brain)
- [@Aetsu's Offensive Pipeline](https://github.com/Aetsu/OffensivePipeline). This project is pretty much a (scuffed and worse) powershell port of OffensivePipeline.
- [@FuzzySec](https://twitter.com/FuzzySec)'s [Discerning Finch](https://github.com/FuzzySecurity/Sharp-Suite/blob/master/DiscerningFinch) - For environmental keying and decrypting - inspired to add encrytion 

## Demo 

![Invoke-PrepareAssembly](/image/invoke_prepareassembly_demo.gif)

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

**JSON file mode - RECOMMENDED**
```
# Import the script 
powershell -exec bypass
. ./Invoke-PrepareAssembly

# All switches at the same time
Invoke-PrepareAssembly -jsonfile ./tools.json -gitclone -compile -obfuscate 

# One switch at a time  
Invoke-PrepareAssembly -jsonfile ./tools.json -gitclone 
Invoke-PrepareAssembly -jsonfile ./tools.json -compile 
Invoke-PrepareAssembly -jsonfile ./tools.json -obfuscate
Invoke-PrepareAssembly -jsonfile ./tools.json -encrypt -key "Hello World"

# Only specific tool 
Invoke-PrepareAssembly -jsonfile ./tools.json -toolname SeatBelt -gitclone -compile -obfuscate -encrypt -key "single key encrypting all tools ohnononono"
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

## TODOs 
Implement and fix donut 

Add confuserEx config to `tools.json` instead?

Support base64 output for compile, obfuscate, encrypt 

Support @rastamouse's dnlib adding assembly to resources to another assembly?
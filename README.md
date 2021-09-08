# Invoke-PrepareAssembly

(scuffed) Powershell script that clones, compiles, obfuscates, donuts, and encrypts .NET assemblies. This project is pretty much a (scuffed and worse) powershell port of OffensivePipeline.

You probably want to use an actual CI/CD pipeline instead of this half-baked powershell script. At most this would be useful for homelabs and personal use.

**All credits goes to :** 
- [@domchell](https://twitter.com/domchell?lang=en) and his mind-blowing CovertToolsmith presentation (galaxy brain)
- [@Aetsu's Offensive Pipeline](https://github.com/Aetsu/OffensivePipeline). This project is pretty much a (scuffed and worse) powershell port of OffensivePipeline.
- [@FuzzySec](https://twitter.com/FuzzySec)'s [Discerning Finch](https://github.com/FuzzySecurity/Sharp-Suite/blob/master/DiscerningFinch) - For environmental keying and decrypting 

## Requirements 
(From OffensivePipeline README) 

1. Build Tools for Visual Studio 2019: https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=BuildTools&rel=16
-  Install .NET Desktop build tools 

2. `nuget.exe, Confuser.CLI.exe, git.exe` in your `PATH` environment. The script will download/recommend these binaries, but you have to manually put these in your PATH. 

3. [.NET 3.5.1](https://www.microsoft.com/en-us/download/details.aspx?id=22) for some tools

4. Turn off Windows Defender you dummy!

## Examples 

Modify the tools.json's output directory 
```
{
    "outDir": "c:\\dev\\testo\\",
    "tools": [
    . . .
```

**JSON file mode**
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
Invoke-PrepareAssembly -jsonfile ./tools.json -toolname SeatBelt -gitclone -compile -obfuscate
```

**Single file mode**
```
Invoke-PrepareAssembly -gitlink <git> -gitclone 

Invoke-PrepareAssembly -slnPath <path_to_sln_file> -compile 

Invoke-PrepareAssembly -inFile <path_to_assembly> -obfuscate 

Invoke-PrepareAssembly -inFile <path_to_assembly> -encrypt -key "Hello World"
```

## Why create a worse version of OffensivePipeline?
I am a wheel re-inventing addict and I wanted to practice writing powershell scripts.
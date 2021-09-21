Function Invoke-PrepareAssembly{
<#
    .DESCRIPTION
    Git clone, compile, obfuscate, and encrypt .NET assemblies. 
    Requires git.exe, msbuild.exe, confuser.cli.exe to be in PATH. 
    RECOMMENDED to modify tools.json file - especially the "outDir".

    .EXAMPLE 
    PS> Invoke-PrepareAssembly -jsonfile ./tools.json -gitclone -compile -obfuscate -encrypt -key "encryptionkey"
    Git clone, compile, obfuscate, and encrypt assemblies inside tools.json, 
    using output directory inside the json 

    .EXAMPLE 
    PS> Invoke-PrepareAssembly -jsonfile ./tools.json -toolName Rubeus -gitclone -compile -obfuscate 
    Git clone, compile, obfuscate specific tool from tools.json 

    .EXAMPLE 
    PS> Invoke-PrepareAssembly -jsonfile ./tools.json -toolName Rubeus -obfuscate 
    Obfuscate specific tool from tools.json file 

    .EXAMPLE 
    PS> Invoke-PrepareAssembly -jsonfile ./tools.json -gitclone 
    Git clone all tools inside tools.json  

    .EXAMPLE 
    PS> Invoke-PrepareAssembly -jsonfile ./tools.json -compile 
    Compile all tools inside tools.json  

    .EXAMPLE 
    PS> Invoke-PrepareAssembly -jsonfile ./tools.json -obfuscate 
    Obfuscate all tools inside tools.json using confuserEx   

    .EXAMPLE 
    PS> Invoke-PrepareAssembly -jsonfile ./tools.json -encrypt -key "encryptionkey" 
    Encrypt all tools inside tools.json using AES256  

    .EXAMPLE 
    PS> Invoke-PrepareAssembly -slnPath c:\tools\Rubeus\Rubeus.sln -outDir c:\Payloads -compile 
    Compile specific project using default setting (Any CPU, dotnet 4.0, Exe)

    .EXAMPLE 
    PS> Invoke-PrepareAssembly -inFile C:\Payloads\Rubeus.exe -outDir C:\Confused -obfuscate 
    Obfuscate specific file using default confuserEx settings 

#>


# My first powershell script! (that is more than 5 lines!) - choi 

# You probably want to use an actual CI/CD pipeline instead of this scuffed script.

# All credits goes to : 
#     - https://github.com/Aetsu/OffensivePipeline. This is Pretty much a (scuffed) powershell port of OffensivePipeline 
#     - https://github.com/FuzzySecurity/Sharp-Suite/blob/master/DiscerningFinch - For environmental keying and decrypting 
#     - covertToolsmith, mdsec, @domchell and his mind-blowing presentation (galaxy brain)

# Notes:
#     - Obfuscation with rules might fail due to wrong .NET version. (ex. assembly uses function from .NET 4.0, but compiled in 3.5) 
#     - Obfuscation might fail from different combinations of rules 

# Are you ready for some spaghetti? Let's go!

    Param(
        [CmdletBinding()]

        [switch]$compile,
        [switch]$obfuscate,
        [switch]$donut, 
        [switch]$prepare, 
        [switch]$prepareAssembly,
        [switch]$gitclone,
        [switch]$encrypt, 

        [Parameter(HelpMessage='.NET assembly solution file path')]
        [string] $slnPath,

        [Parameter(HelpMessage='Output directory path')]
        [string] $outDir,

        [Parameter(HelpMessage='Input file path to obfuscate')]
        [string] $inFile, 

        [Parameter(Mandatory=$false, HelpMessage='Obfuscation level: minimum, normal, aggressive, maximum. Default is normal.')]
        [string] $level = "normal",

        [Parameter(Mandatory=$false, HelpMessage='Target Architecture. x86, x64, or "Any CPU". Default is Any CPU')]
        [string] $arch = "Any CPU",

        [Parameter(Mandatory=$false, HelpMessage='Output type of the assembly. Exe or Library. Default is Exe.')]
        [string] $outputType = "exe",

        [Parameter(Mandatory=$false, HelpMessage='Dotnet version. Default is 4.0')]
        [string] $dotnetVersion = "v4.0",

        [Parameter(Mandatory=$false, HelpMessage='ConfuserEx configuration XML file path. If not provided, use a default one.')]
        [string] $confuserConfig = 
@"
<project outputDir="{{OUTPUT_DIR}}" baseDir="{{BASE_DIR}}" xmlns="http://www.google.com">
    <!-- <packer id="compressor" /> --> <!-- this breaks DLL files "No executable module". Use if you are only obfuscating exe files --> 
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
        [Parameter(HelpMessage='Donut arguments')]
        [string] $donutArgs,

        [Parameter(HelpMessage='Yaml file containing projects to build')]
        [string] $jsonFile,

        [Parameter(HelpMessage='Specific Tool from JSON file')]
        [string] $toolName,

        [Parameter(HelpMessage='Github link to clone')]
        [string] $gitLink,

        [Parameter(HelpMessage='Plaintext key to AES256 encrypt assembly')]
        [string] $key 
    )

#     <project outputDir="{{OUTPUT_DIR}}" baseDir="{{BASE_DIR}}" xmlns="http://www.google.com">
#     <!-- <packier id="compressor" /> --> <!-- Breaking a bunch of assemblies, commenting it out --> 
#     <rule pattern="true" preset="{{LEVEL}}" inherit="false">
#         <protection id="anti ildasm" />
#         <protection id="anti debug" action="remove" /> <!-- this breaks Assembly.Load. Maybe just use donut?  -->
#         <protection id="anti dump" />
#         <protection id="anti tamper" action="remove" /> <!-- this breaks Assembly.Load. Maybe just use donut?  -->
#         <protection id="invalid metadata" />
#         <protection id="resources" />
#         <protection id="constants" />
#         <protection id="ctrl flow" />
#         <protection id="rename" action="remove" /> <!-- This just killed seatbelt for some reason --> 
#     </rule>

#     <module path="{{MODULE_PATH}}" />
# 

    # https://github.com/atmchile/powershell/blob/master/find-msbuild.ps1
    # Only return 1 instance of msbuild foudn through resolve-path 
    function Find-MsBuild()
    {
        # 2017, 2019
        $msbuild = (Resolve-Path "${env:ProgramFiles(x86)}\Microsoft Visual Studio\*\*\MSBuild\*\bin\msbuild.exe" -EA 0)[0]
        If ((Test-Path $msbuild)) { return $msbuild } 

        # 2013 (12.0), 2015 (14.0)
        $msbuild = (Resolve-Path "${Env:ProgramFiles(x86)}\MSBuild\*\Bin\MSBuild.exe" -EA 0)[0]
        If ((Test-Path $msbuild)) { return $msbuild } 

        # 4.0
        $msbuild = "${env:WinDir}\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe"
        If (Test-Path $msbuild) { return $msbuild } 

        throw "Unable to find msbuild"
    }
    
    Function checkCommand($cmdName){
        if(Get-Command $cmdName -ErrorAction SilentlyContinue){
            return $true
        }
        else{
            return $false
        }
    }

    # Initial check - See if required binaries are inside current PATH. If not, download and suggest. 
    # Return: 
    #   - 0 : All commands exist
    #   - 1 : Some command doesn't exist
    Function initCheck(){
        $initCheckResult = 0 

        $cmds = @('git.exe', 'nuget.exe', 'Confuser.CLI.exe')

        $downloadDir = New-Item -Path "utilTools" -ItemType Directory -Force
        Write-Host "[+] Creating Downloads directory $downloadDir" -ForegroundColor Green

        # Check for msbuild.exe first 
        $msbuild = (Find-MsBuild).Path
        if(-not $msBuild){
            Write-Host "[-] Msbuild does not exist" -ForegroundColor Red 
            return 1 
        }

        Write-Host "[+] msBuild.exe location: $msBuild" -ForegroundColor Green 

        # Check git, nuget, confuser. Not having donut.exe is fine tho. 
        foreach($cmd in $cmds){
            if (-not(checkCommand($cmd))){
                # If one command doesn't exist, function returns "1" - fail 
                $initCheckResult = 1 

                Write-Host "[-] $cmd does not exist in PATH." -ForegroundColor Red
                Write-Host "[*] Downloading necessary files in 5 seconds ..." -ForegroundColor Red
                Start-Sleep -Seconds 5

                # Download, unzip, etc. Depending on which commands are missing 
                switch ($cmd.ToLower()) {
                    "nuget.exe" {
                        $nugetPath = Join-Path -Path $downloadDir -ChildPath $cmd
                        (New-Object System.Net.WebClient).DownloadFile("https://dist.nuget.org/win-x86-commandline/latest/nuget.exe", $nugetPath)
                        Write-Host "[*] Downloaded $cmd in $nugetPath" 
                      }
                    
                    "confuser.cli.exe" {
                        $confuserPath = Join-Path -Path $downloadDir -ChildPath "confuser.zip"
                        (New-Object System.Net.WebClient).DownloadFile("https://github.com/mkaring/ConfuserEx/releases/download/v1.5.0/ConfuserEx-CLI.zip", $confuserPath)
                        Expand-Archive -Path $confuserPath -DestinationPath $confuserPath.split('.')[0]  -Force 
    
                        Write-Host "[*] Downloaded $cmd and unzipped in $confuserPath ..." 
                    }
                    "git.exe" {
                        Write-Host "[*] Download git from here: https://github.com/git-for-windows/git/releases/"
                    }

                    "donut.exe" {
                        $donutPath = Join-Path -Path $downloadDir -ChildPath "donut.zip"
                        (New-Object System.Net.WebClient).DownloadFile("https://github.com/TheWover/donut/releases/download/v0.9.3/donut_v0.9.3.zip", $donutPath)
                        Expand-Archive -Path $donutPath -DestinationPath $donutPath.split('.')[0] -Force 
                        
                        Write-Host "[*] Downloaded donut and unzipped $donutPath" 
                    }
                }           
            }

            # Cmd exists, we are good. 
            else{
                Write-Host "[+] $cmd is in PATH" -ForegroundColor Green 
                # no new line if cmd exists
                continue 
            }

            Write-Host ""
        }

        if($initCheckResult -eq 1){
            Write-Host "[*] Your Path: $($Env:Path)" 
            Write-Host "[*] Install or move necessary binaries and their DLLs to your PATH.`n[*] Or just add those paths into your PATH." -ForegroundColor Green
            return 1
        }
    
        # Check msbuild.exe executable. Grab the first one if multiple found. 
        Write-Host "`n[+] All necessary cmds are here. Good to go.`n" -ForegroundColor Green
        Write-Host "------------------------------------------------------------`n"

        return 0 
    }

    <# Modified from https://stackoverflow.com/questions/5313719/how-to-find-reference-path-via-csproject-file #>
    Function copyReferences($slnPath, $outDir, $confuserConfig){
        $slnDir = Split-Path -Path $slnPath -Parent
        $projectFiles = Get-ChildItem $slnDir *.csproj -Recurse 

        # Go through .csproj and look for "hintPath". If such references exist, copy those dll files to outDir.
        foreach ($projectFile in $projectFiles) {
            $projectXml = [xml](Get-Content $projectFile.FullName)
            $projectDir = $projectFile.DirectoryName

            
            foreach ($itemGroup in $projectXml.Project.ItemGroup) {
                if($itemGroup.Reference.Count -eq 0 ){
                    continue 
                }

                foreach ($reference in $itemGroup.Reference) {
                    if($reference.Include -eq $null){
                        continue 
                    }

                    if($reference.HintPath -ne $null)
                    {
                        $fullpath = $reference.HintPath
                        if(-not [System.IO.Path]::IsPathRooted( $fullpath ) )
                        {
                            $fullPath = (join-path $projectDir $fullpath)
                            $fullPath = [System.IO.Path]::GetFullPath("$fullPath")
                        }

                        if( $fullPath.ToLower().Contains($slnDir.ToLower()) ){
                            $addModule = "    <module path=`"$fullPath`" />"
                            $confuserConfig = $confuserConfig + "`n" + $addModule
                            Write-Host "[+] Copying Reference: $fullPath to outdir: $outDir"
                            # Not copying refernce dll because the full path goes into confuserEx config file now
                            # Apparently the dll needs to be in the same path 
                            Copy-Item -Path $fullpath -Destination $outDir -Force 
                        }

                    }
                   
                }
            }
        }

        # Modify the confuser Config and return the complete confuser config back
        $finishConfig = "</project>"
        $returnConfuserConfig = $confuserConfig + "`n" + $finishConfig

        return $returnConfuserConfig
    }

    # Nullify AssemblyInfo.cs and change GUID to random GUID. 
    Function nullAssemblyInfo($slnPath){
        $assemblyInfoPath = (Get-ChildItem -Path (Get-Item $slnPath).Directory.FullName -Filter "AssemblyInfo.cs" -Recurse).FullName
    
        (Get-Content $assemblyInfoPath) | foreach-Object{
            if($_ -Match "Title"){ '[assembly: AssemblyTitle("{0}")]' -f [String]::Empty } 
            elseif($_ -Match "Description"){ '[assembly: AssemblyDescription("{0}")]' -f [String]::Empty }
            elseif($_ -Match "Product"){ '[assembly: AssemblyProduct("{0}")]' -f [String]::Empty }
            elseif($_ -Match "Copyright"){ '[assembly: AssemblyCopyright("{0}")]' -f [String]::Empty }
            elseif($_ -Match "assembly: Guid"){ '[assembly: Guid("{0}")]' -f (New-Guid).Guid }
            else{ $_ }
        } | Set-content $assemblyInfoPath
    }

    # Change AssemblyName in csproj, Nullout AssemblyInfo 
    # Returns assembly name of random string of 8 characters 
    Function changeAssemblyName($slnPath) {
        # Change AssemblyName 
        $csprojFile = (Get-ChildItem -Path (Get-Item $slnPath).Directory.FullName "*.csproj" -Recurse).FullName
        $xmlObj = [xml](Get-Content -Path $csprojFile)
        $newAssemblyName = -join ((48..57) + (97..122) | Get-Random -Count 8 | % {[char]$_})
        $xmlObj.Project.PropertyGroup[0].AssemblyName = $newAssemblyName
        $xmlObj.Save($csprojFile)

        return $newAssemblyName
    }

    # Compile .NET assembly using msbuild. Specify output directory, arch (x86/64), outputType(exe,dll), dotnetVersion 
    # Delets AssemblyInfo.cs and change GUID from the slnPath 
    # Returns slnPath (parse toolName) + randomName returned from changeAssembly Name
    # TODO: Documentation and 1.2.3. .. 
    Function compile ($slnPath, $outDir, $arch, $outputType, $dotnetVersion){
        Write-Host "[+] Compiling $slnPath ..."

        if(-not (Test-Path $slnPath -PathType Leaf)){
            Write-Host "[-] Can't find solution file. Exiting." -ForegroundColor Red 
            return 
        }

        # 1. Restore nuget 
        Write-Host "[+] Nuget restoring packages, if there are any"
        nuget restore $slnPath 2>&1 | Out-Null 

        # 2. Configure confuserEx configuration file 
        $msbuildTemplate = "{{SOLUTION_PATH}} /p:Platform=`'{{ARCH}}`' /p:OutputPath=`'{{OUTPUT_DIR}}`' /p:DebugSymbols=false /p:DebugType=None /p:OutputType={{OUTPUT_TYPE}} /p:TargetFrameworkVersion={{DOTNETVERSION}}"
        $msbuildOptions = $msbuildTemplate.
        replace("{{SOLUTION_PATH}}", $slnPath).
        replace("{{ARCH}}", $arch).
        replace("{{OUTPUT_DIR}}", $outDir).
        replace("{{OUTPUT_TYPE}}", $outputType).
        replace("{{DOTNETVERSION}}", $dotnetVersion)

        Write-Host "[*] Build options: $msbuildOptions"

        Write-Host "[+] Building $slnPath ..." 
        $msbuild = (Find-MsBuild).Path

        # 3. Change assemblyName and remove assemblyInfo metadata 
        $randomAssemblyName = changeAssemblyName($slnPath)
        
        # 4. Nullify AssemblyInfo.cs and generate fake GIUD 
        nullAssemblyInfo($slnPath)

        # 5. Actually compile the assembly using msbuild 
        #$output = Invoke-Expression "& `"$msbuild`" $msbuildOptions"
        $output = Invoke-Expression "& `"$msbuild`" $msbuildOptions" | Out-Null

        # Go through outDir, find file with <randomAssemblyName> that ends with .exe or .dll. Parse Toolname from slnPath, and change that file's name to <tool>_<name>
        $assemblyFile = (Get-Childitem $outDir | Where-Object { ($_ -match $randomAssemblyName) -and ( ($_.Extension -eq ".dll") -or ($_.Extension -eq ".exe") )  }).FullName
        $toolName = (Get-Item $slnPath).Directory.Name
        $finalAssemblyName = ($toolName + "_" + $randomAssemblyName + "." + $assemblyFile.split('.')[1])
        Rename-Item $assemblyFile -NewName $(Join-Path -Path $outDir -ChildPath $finalAssemblyName)        

        if ($LastExitCode -ne 0)
        {
            Write-Host "[-] msBuild failed" -ForegroundColor Red
            Write-Host "ERROR: $output"
            return
        }
        
        Write-Host "[+] Compiling successful: $finalAssemblyName`n`n" -ForegroundColor Green
    }

    <# Create "Confused" directory and then  #>
    Function obfuscate ($inFile, $outDir, $slnPath, $confuserConfig, $level) {
        #Write-Host "[+] Obfuscation level: $level"

        # Error checking for inFile. Does it exist?
        if (-not (Test-Path -Path $inFile -PathType leaf) -or -not(Test-Path -Path $outDir)){
            Write-Host "[-] Eiter $inFile or $outDir does not exist" -ForegroundColor Red 
            return 
        }

        # Error check here 
        if(-not (Test-Path -Path $(Join-Path -Path $outDir -ChildPath "Confused"))){
            try{
                New-Item -Path $outDir -Name "Confused" -ItemType "Directory" -Force | Out-Null
                Write-Host "[+] Created Confused directory: $confusedDir"
            }
            catch{
                Write-Host "[-] Could not create Confused directory. Exiting." -ForegroundColor Red 
                return 
            }
        }

        $confusedDir = Join-Path $outDir -ChildPath "Confused"

        # TODO: Implement this. If user provided confuserex config file, try opening up and read it 
        if( (Test-Path -Path $confuserConfig -PathType leaf) ){
            try{
                $confuserConfigTemplate = Get-Content $confuserConfig -Raw
            }
            catch {
                Write-Host "[-] Confuser configuration file error: " $_.Exception.Message -ForegroundColor Red 
                return 
            } 
        }

        else{
            Write-Host "[*] Confuserex config file not provided. Using the default one." 

            $baseDir = Split-Path -Path $inFile
            $updatedConfuserConfig = $confuserConfig.
            Replace("{{OUTPUT_DIR}}", $confusedDir).
            Replace("{{BASE_DIR}}", $baseDir).
            Replace("{{MODULE_PATH}}", $inFile).
            Replace("{{LEVEL}}", $level)
        }

        # Updating confuserEx config with references, if they exist. 
        $finalConfuserConfig = copyReferences $slnPath $outDir $updatedConfuserConfig | Select-Object -Last 1

        $confuserConfigFilePath = $confusedDir + "\" + $(Split-Path $inFile -leaf) + ".crproj"
        $finalConfuserConfig | Out-File -FilePath $confuserConfigFilePath
        
        Confuser.CLI.exe -n $confuserConfigFilePath | Out-Null
        # debug
        #Confuser.CLI.exe -n $confuserConfigFilePath 

        # If first confuser fails, it might be because of adding module Paths from copyReferences. Retry with a simple confuserEx config.
        if ($LastExitCode -ne 0)
        {
            $updatedConfuserConfig = $updatedConfuserConfig + "`n</project>"
            $updatedConfuserConfig | Out-File -FilePath $confuserConfigFilePath
            Write-Host "[+] First try failed. Retrying..." -ForegroundColor Red
            Confuser.CLI.exe -n $confuserConfigFilePath | Out-Null
            # debug
            #Confuser.CLI.exe -n $confuserConfigFilePath 

            # If second confuser fails, I have no idea. Exit. 
            if ($LastExitCode -ne 0){
                Write-Host "[-] Obfuscation failed. Suggest manually obfuscating using ConfuserEx GUI`n" -ForegroundColor Red
                return  
            }
            else{
                Write-Host "[+] 2nd try succeeded" -ForegroundColor Green
                Write-Host "[+] Obfuscation successful: $confusedDir\$(Split-Path -Path $inFile -Leaf)`n" -ForegroundColor Green 
            }
        }
        else{
            Write-Host "[+] Obfuscation successful: $confusedDir\$(Split-Path -Path $inFile -Leaf)`n" -ForegroundColor Green 
        }
    }

    <# https://www.powershellgallery.com/packages/DRTools/4.0.2.3/Content/Functions%5CInvoke-AESEncryption.ps1 #>
    Function aes256Encrypt($inFile, $key){
        $shaManaged = New-Object System.Security.Cryptography.SHA256Managed
        $aesManaged = New-Object System.Security.Cryptography.AesManaged
        $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $aesManaged.BlockSize = 128
        $aesManaged.KeySize = 256

        $aesManaged.Key = $shaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($key)) 

        $file = Get-Item -Path $inFile -ErrorAction SilentlyContinue 
        if(!$file.FullName){
            Write-Host -Message "[-] File not found" -ForegroundColor Red
            return 
        }

        $plainBytes = [System.IO.File]::ReadAllBytes($inFile) 
        $outFilePath = $file.FullName + ".aes"

        $encryptor = $aesManaged.CreateEncryptor()
        $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length) 
        $encryptedBytes = $aesManaged.IV + $encryptedBytes
        
        [System.IO.File]::WriteAllBytes($outFilePath, $encryptedBytes)
        Write-Host "[+] Encrypted assembly written: $outFilePath" -ForegroundColor Green

        $shaManaged.Dispose()
        $aesManaged.Dispose()
    }

    # https://github.com/TheWover/donut
    Function donut ($inFile, $donutArgs){
        Write-Host "[+] Uh, I'm just running donut at this point lol"
        $finalDonutArgs = $inFile + " " + $donutArgs
        donut.exe $finalDonutArgs
    }

    # TODO: Should probably make into a prompt and go step-by-step like a wizard 
    Function prepareAssembly ($slnPath, $outDir){
        try{
            compile $slnPath $outDir
        }
        catch {
            Write-Host "[-] Compile failed:" $_.Exception.Message 
            return 
        }

        # Find all items in confused directory, that ends with .exe or .dll
        $inFilePath = $outDir
        $inFiles = Get-ChildItem $inFilePath -Include ("*.exe", "*.dll") -Name
        $inFile = ""
        foreach ($item in $inFiles) {
            if( ((Get-Item $slnPath).BaseName.Contains($item.ToString()) ) -or ($item.ToString().Contains((Get-Item $slnPath).BaseName)) ){
                $inFile = $inFilePath.ToString() + $item.ToString()
                break
            }
        }

        if($inFile -eq ""){
            Write-Host "[-] Unable to find file to obfuscate. Exiting." -ForegroundColor Red
            return 
        }

        try{
            obfuscate $inFile $outDir $confuserConfig $level
        }
        catch {
            Write-Host "[-] Obufscate failed:" $_.Exception.Message 
            return 
        }

        try{
            donut $inFile
        }
        catch {
            Write-Host "[-] Donut failed:" $_.Exception.Message 
            return 
        }
    }

    Function gitClone($gitLink, $outDir){
        $toolPath = Join-Path -Path $outDir -ChildPath ([io.fileinfo](Split-Path $gitLink -Leaf)).BaseName
        if(Test-Path -Path $toolPath){
            Write-Host "[*] Tool already exists. Not git-cloning."
            return 
        }


        Write-Host "[*] Tool does not exist. Cloning to: $toolPath"
        git clone $gitLink $toolPath | Out-Null

        if ($LastExitCode -ne 0)
        {
            Write-Host "[-] Git cloning failed" -ForegroundColor Red
            Write-Host $output
            return
        }
        else{
            Write-Host "[+] Git cloning successful: $toolPath`n`n" -ForegroundColor Green
        }
    }



    <#
       ===================================================================================================
       ================================= Argument process & Main Logic ===================================
       ===================================================================================================
    #>

    if(initCheck -eq 1){
        return 
    }

    <# If jsonFile given, update the variables #>
    if($jsonFile){
        # powershell ignores variable scope inside if statements?!
        $jsonData = (Get-Content -Raw -Path $jsonFile | ConvertFrom-Json)
        $outDir = $jsonData.outDir 

        if(!(Test-Path -Path $jsonData.outDir)){
            Write-Host "[-] Path does not exist. Creating path."
            New-Item -Path $jsonData.outDir -ItemType "Directory" | Out-Null
        }
    }

    <# Git clone #>
    if($gitclone){

        # Git clone specific tool inside jsonFile 
        if($jsonFile -and $toolName){
            foreach ($tool in $jsonData.tools) {
                if($toolName.ToLower() -like ($tool.Name).ToLower()){
                    gitClone $tool.gitLink $jsonData.outDir 
                }
            }
        }

        # Git clone all tools inside jsonFile 
        elseif($jsonFile){
            foreach ($tool in $jsonData.tools) {
                gitClone $tool.gitLink $jsonData.outDir 
            }
        }

        # Git clone specific tool from user parameter 
        elseif($gitLink -and $outDir){
            gitClone $gitLink $outDir 
        }

        else{
            Write-Host "[-] Git cloning failed. Wrong parameter combination. Exiting." -ForegroundColor Red
            return 
        }
    }

    <# Compile  #>
    if($compile){

        # Compile specific tool inside jsonFile 
        if ($jsonFile -and $toolName){
            Write-Host "[+] Compiling $toolName"
            foreach ($tool in $jsonData.tools) {
                if($toolName.ToLower() -like ($tool.Name).ToLower()){
                    $slnPath = Join-Path -Path $outDir -childPath $tool.slnPath
                    compile $slnPath $outDir $tool.arch $tool.outputType $tool.dotnetVersion
                }
            }
        }

        # Compile all tools inside jsonFile 
        elseif ($jsonFile){
            foreach ($tool in $jsonData.tools) {
                $slnPath = Join-Path -Path $outDir -childPath $tool.slnPath
                compile $slnPath $outDir $tool.arch $tool.outputType $tool.dotnetVersion
            }
        }

        # Compile specific tool the user wants 
        elseif(-not $jsonFile){
            #if(-not ($slnPath -or $outDir -or $arch -or $outputType -or $dotnetVersion)){
            #    Write-Host "[-] Need slnPath, outDir, arch, outputType, and dotnetVersion." -ForegroundColor Red
            #    Write-Host "[-] Wrong parameter combination. Exiting." -ForegroundColor Red 
            #}
            compile $slnPath $outdir $arch $outputType $dotnetVersion
        }

        else{
            Write-Host "[-] Wrong parameter combination. Exiting." -ForegroundColor Red
            return 
        }
    }

    <# Obufscate #>
    if($obfuscate){
        try{
            # get all dll or exe filenames from outdir, in descending order of time 
            $inFiles = (Get-ChildItem $outDir | Where-Object { ($_.Extension -eq ".dll") -or ($_.Extension -eq ".exe") } | Sort-Object CreationTime -Descending ).Name
        }
        catch{
            Write-Host "[-] Cannot find any PE files in $outDir . Exiting." -ForegroundColor Red
            return 
        }

        # Obufscate specific tool inside jsonFile 
        if ($jsonFile -and $toolName){
            #Write-Host "[+] Default confuserConfig = $confuserConfig"
            foreach ($inFile in $inFiles) {
                if( $inFile.ToLower().Contains( $toolName.ToLower())) {
                    if ($inFile.EndsWith('.dll') -or $inFile.EndsWith('.exe')){
                        $toolslnPath = $jsonData.tools | where{$_.Name -eq $toolName} | Select-Object -ExpandProperty slnPath
                        $finalToolslnPath = Join-Path -Path $outDir -ChildPath $toolslnPath
                        $inFile = Join-Path -Path $outDir -ChildPath $inFile

                        obfuscate $inFile $outDir $finalToolslnPath $confuserConfig $level 

                        # Found the most recent one, and obfuscated. Break out and finish. 
                        break
                    }
                }
            }
        }

        # Obfuscate all tools inside jsonFile 
        elseif($jsonFile){
            #Write-Host "[+] Default confuserConfig = $confuserConfig"
            foreach ($toolName in ($jsonData.tools.Name).ToLower()) {
                foreach ($inFile in $inFiles) {
                    if ($inFile.ToLower().Contains($toolName.ToLower())) {
                        $inFile = Join-Path -Path $outDir -ChildPath $inFile
                        $toolslnPath = $jsonData.tools | Where-Object {$_.Name -eq $toolName} | Select-Object -ExpandProperty slnPath
                        $finalToolslnPath = Join-Path -Path $outDir -ChildPath $toolslnPath

                        Write-Host "[+] Obfuscating $inFile" 
                        obfuscate $inFile $outDir $finalToolslnPath $confuserConfig $level   

                        # If the most (inFiles is sorted descending) tool is obfuscated, continue to next tool 
                        break     
                    }

                    # If the most (inFiles is sorted descending) tool is obfuscated, continue to next tool 
                    continue
                }
            }
        }

        # Obfuscate specific tool with filepath 
        elseif($inFile -and $outDir -and $slnPath){
            obfuscate $inFile $outDir $slnPath $confuserConfig $level 
        }

        else{
            Write-Host "[-] Wrong parameter combination. Exiting." -ForegroundColor Red
            return 
        }
    }

    <# Encrypt with AES256 #>
    if($encrypt){

        # Encrypt invidivual file  
        if (-not $jsonFile -and ($inFile -and $key)){
            Write-Host "[+] AES256 Encrypting $inFile with $key ..."
            aes256Encrypt $inFile $key
        }

        # Encrypt tools within jsonFile  
        elseif ($jsonFile -and $key) {
            $userAnswer = Read-Host "`n[+] Encrypt [confused/compiled] assemblies ?"

            Write-Host "`n[+] Encrypting .exe/.dll assemblies from confused/compiled directory ..."
            Write-Host "[+] Encrypting begins in 5 seconds"
            Start-Sleep -Seconds 5

            $confusedDir = Join-Path -Path $outDir -ChildPath "Confused"
            if ($userAnswer.ToLower() -eq "confused"){
                $inFiles = (Get-ChildItem $confusedDir | Where-Object { ($_.Extension -eq ".dll") -or ($_.Extension -eq ".exe") }).Name
                $encryptPath = $confusedDir
            }
            elseif($userAnswer.ToLower() -eq "compiled"){
                $inFiles = (Get-ChildItem $outDir | Where-Object { ($_.Extension -eq ".dll") -or ($_.Extension -eq ".exe") }).Name
                $encryptPath = $outDir
            }
            else{
                Write-Host "[-] Please choose confused or compiled" -ForegroundColor Red
                return
            }

            # Encrypting specific tool with -toolName 
            if($toolName){
                foreach ($tool in $jsonData.tools.name) {
                    foreach ($inFile in $inFiles) {
                        if($inFile.ToLower().Contains($toolName.ToLower())) {
                            $inFile = Join-Path -Path $encryptPath -ChildPath $inFile
                            aes256Encrypt $inFile $key
                            break
                        }
                    }
                    break
                }
            }

            # Encrypting all tools inside json file
            else{
                foreach ($tool in $jsonData.tools.name) {
                    foreach ($inFile in $inFiles) {
                        if($inFile.ToLower().Contains($tool.ToLower())) {
                            $inFile = Join-Path -Path $encryptPath -ChildPath $inFile
                            aes256Encrypt $inFile $key
                            break
                        }
                    }
                }
            }
        }
    }

    # tools.json file not supported as of now 
    # TODO: Implement tools.json
    if ($donut){
        if($inFile){
            Write-Host "[+] Donutting $inFile with default arguments" -ForegroundColor Green
            $donutArgs = ""
            donut.exe $inFile $donutArgs
            Write-Host "`n[+] Output donutted file in current directory" -ForegroundColor Green 
        }
        elseif ($inFile -and $donutArgs) {
            Write-Host "[+] Donutting $inFile with $donutArgs" -ForegroundColor Green
            donut.exe $inFile $donutArgs 
        }
        else{
            Write-Host "[-] Wrong parameter combination. Either give me 'inFile' or 'donutArgs' " -ForegroundColor Red
            return 
        }
    }
}
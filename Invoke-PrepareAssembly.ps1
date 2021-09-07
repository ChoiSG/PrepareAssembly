Function Invoke-PrepareAssembly{

<#
    My first (more than 5 lines of) powershell script! - choi 

    You probably want to use an actual CI/CD pipeline instead of this scuffed script.

    All credits goes to : 
        - https://github.com/Aetsu/OffensivePipeline. This is Pretty much a (scuffed) powershell port of OffensivePipeline 
        - https://github.com/FuzzySecurity/Sharp-Suite/blob/master/DiscerningFinch - For environmental keying and decrypting 
        - covertToolsmith, mdsec, @domchell and his mind-blowing presentation (galaxy brain)
    
    TODO: 
        - Include tools like confuserexCLI and nuget with the script. 
        - Review architecture & dotnetversion and implement correctly. Currently just using default values 
        - Fix SharpGPOAbuse & ConfuserEx problem? 

        - Some executables have same dll references with different versions. Just copying over 
        these references in same folder will overwrite each dlls. This might be okay for compiling, will 
        make obfuscation to fail. 

        - Obfuscate - add modulepath if copyReference exists 
#>

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

        [Parameter(Mandatory=$false, HelpMessage='Output type of the assembly. exe or dll. Default is exe.')]
        [string] $outputType = "exe",

        [Parameter(Mandatory=$false, HelpMessage='ConfuserEx configuration XML file path. If not provided, use a default one.')]
        [string] $confuserConfig = 
@"
<project outputDir="{{OUTPUT_DIR}}" baseDir="{{BASE_DIR}}" xmlns="http://www.google.com">
    <packer id="compressor" />  
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
    function Find-MsBuild()
    {
        # 2017, 2019
        $msbuild = Resolve-Path "${env:ProgramFiles(x86)}\Microsoft Visual Studio\*\*\MSBuild\*\bin\msbuild.exe" -EA 0
        If ((Test-Path $msbuild)) { return $msbuild } 

        # 2013 (12.0), 2015 (14.0)
        $msbuild = Resolve-Path "${Env:ProgramFiles(x86)}\MSBuild\*\Bin\MSBuild.exe" -EA 0
        If ((Test-Path $msbuild)) { return $msbuild } 

        # 4.0
        $msbuild = "${env:WinDir}\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe"
        If (Test-Path $msbuild) { return $msbuild } 

        throw "Unable to find msbuild"
    }
    
    Function checkCommand($cmdName){
        try{
            $cmdName | Out-Null
        }
        catch [System.Management.Automation.CommandNotFoundException]{
            return $false
        }
        return $true
    }

    <# TODO: Check necessary binaries and PATH. #>
    Function initCheck(){
        $cmds = @('git.exe', 'nuget.exe', 'Confuser.CLI.exe')

        $downloadDir = New-Item -Path "utilTools" -ItemType Directory -Force
        Write-Host "[+] Creating Downloads directory $downloadDir" -ForegroundColor Green

        foreach($cmd in $cmds){
            if (-not(checkCommand($cmd))){
                Write-Host "[-] $cmd does not exist in PATH."
                Write-Host "[*] Downloading necessary files in 5 seconds ..."
                Start-Sleep -Seconds 5 
                
                # Nuget CLI does not exist. Download 
                if ($cmd.ToLower() -eq "nuget.exe"){
                    $nugetPath = Join-Path -Path $downloadDir -ChildPath $cmd
                    (New-Object System.Net.WebClient).DownloadFile("https://dist.nuget.org/win-x86-commandline/latest/nuget.exe", $nugetPath)
                    Write-Host "[+] Downloaded $cmd in $nugetPath" -ForegroundColor Green
                }

                # ConfuserExCLI does not exist. Download & Unzip confuserex 
                elseif ($cmd.tolower() -eq "confuser.cli.exe") {
                    $confuserPath = Join-Path -Path $downloadDir -ChildPath "confuser.v1.4.1.zip"
                    (New-Object System.Net.WebClient).DownloadFile("https://github.com/mkaring/ConfuserEx/releases/download/v1.4.1/ConfuserEx-CLI.zip", $confuserPath)
                    Write-Host "[+] Downloaded $cmd in $confuserPath" -ForegroundColor Green

                    Expand-Archive -Path $confuserPath 
                    Write-Host "[+] Unzipping $confuserPath ..."
                }

                # Git CLI does not exist. Output github for windows releases 
                elseif ($cmd.ToLower() -eq "git.exe"){
                    Write-Host "[*] Download git from here: https://github.com/git-for-windows/git/releases/"
                }

                Write-Host "[*] Your Path: $($Env:Path)"
                Write-Host "[*] Install and move necessasry binaries, or add necessary path to your PATH"
                return 
            }

            else{
                Write-Host "[+] $cmd is in PATH"
            }
        }
    
        # Check msbuild.exe executable. Grab the first one if multiple found. 
        $msbuild = (Find-MsBuild).Path[0]
        Write-Host "[+] $msbuild is in PATH" 
    
        Write-Host "[+] All necessary cmds are here. Good to go.`n`n"
    }

    <# https://stackoverflow.com/questions/5313719/how-to-find-reference-path-via-csproject-file #>
    Function copyReferences($slnPath, $outDir, $confuserConfig){
        $slnDir = Split-Path -Path $slnPath -Parent

        $projectFiles = Get-ChildItem $slnDir *.csproj -Recurse 

        $references = [System.Collections.ArrayList]@()

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
                            $references.Add($fullPath)
                            # <module path="{{MODULE_PATH}}" />
                            $addModule = "    <module path=`"$fullPath`" />"
                            $confuserConfig = $confuserConfig + "`n" + $addModule
                            Write-Host "[+] Copying Reference: $fullPath to outdir: $outDir"
                            Copy-Item -Path $fullpath -Destination $outDir -Force 
                        }

                    }
                   
                }
            }
        }

        $finishConfig = "</project>"
        $returnConfuserConfig = $confuserConfig + "`n" + $finishConfig
        Write-Host "[+] Final Config = $returnConfuserConfig"

        $returnConfuserConfig
        return  
        #return $references

    }

    # TODO: Implement Arch and Dotnet version 
    Function compile ($slnPath, $outDir, $arch, $outputType){
        Write-Host "[+] Compiling $slnPath ..."

        if(-not (Test-Path $slnPath -PathType Leaf)){
            Write-Host "[-] Can't find solution file. Exiting." -ForegroundColor Red 
            return 
        }

        Write-Host "[+] Nuget restoring packages, if there are any"
        nuget restore $slnPath 2>&1 | Out-Null 

        # TODO: Implement /p:TargetFrameworkVersion and OutputType (Exe, Library)
        $msbuildTemplate = "{{SOLUTION_PATH}} /p:Platform=`'{{ARCH}}`' /p:OutputPath=`'{{OUTPUT_DIR}}`' /p:DebugSymbols=false /p:DebugType=None /p:OutputType={{OUTPUT_TYPE}}"
        $msbuildOptions = $msbuildTemplate.
        replace("{{SOLUTION_PATH}}", $slnPath).
        replace("{{ARCH}}", $arch).
        replace("{{OUTPUT_DIR}}", $outDir).
        replace("{{OUTPUT_TYPE}}", $outputType)

        Write-Host "[DEBUG] Build options: $msbuildOptions"


        # Actually building 
        Write-Host "[+] Building $slnPath ..." 
        $msbuild = (Find-MsBuild).Path[0]

        $output = Invoke-Expression "& `"$msbuild`" $msbuildOptions" | Out-Null

        if ($LastExitCode -ne 0)
        {
            Write-Host "[-] msBuild failed" -ForegroundColor Red
            Write-Host "ERROR: $output"
            return
        }

        #Write-Host "[+] Copying References for obfuscation... "
        #copyReferences $slnPath $outDir $confuserConfig
        
        Write-Host "[+] Compiling successful: $([System.IO.Path]::GetFileNameWithoutExtension($slnPath))`n`n" -ForegroundColor Green
    }

    <# Create "Confused" directory and then  #>
    Function obfuscate ($inFile, $outDir, $slnPath, $confuserConfig, $level) {

        Write-Host "[+] Obfuscation level: $level"

        # Error checking for inFile. Does it exist?
        if (-not (Test-Path -Path $inFile -PathType leaf) -or -not(Test-Path -Path $outDir)){
            Write-Host "[-] Obfuscate failed. Eiter $inFile or $outDir does not exist" -ForegroundColor Red 
            return 
        }

        # Error check here 
        if(-not (Test-Path -Path $(Join-Path -Path $outDir -ChildPath "Confused"))){
            try{
                New-Item -Path $outDir -Name "Confused" -ItemType "Directory" -Force
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
            $finalConfuserConfig = $confuserConfig.
            Replace("{{OUTPUT_DIR}}", $confusedDir).
            Replace("{{BASE_DIR}}", $baseDir).
            Replace("{{MODULE_PATH}}", $inFile).
            Replace("{{LEVEL}}", $level)
            

            #$references = copyReferences $slnPath $outDir
            #foreach ($item in $references) {
            #    Write-Host $references
            #}
        
            # So we should just use current directory or something, or create a new directory 
        }

        #$confuserConfigFilePath = $confusedDir + "\" + $(Split-Path $inFile -leaf) + ".crproj"
        #$finalConfuserConfig | Out-File -FilePath $confuserConfigFilePath

        # Updating confuser config with references, if they exist. 
        # powershell weird with returning result of all commands and then the function return value wtf 
        $finalConfuserConfig = copyReferences $slnPath $outDir $finalConfuserConfig | Select-Object -Last 1

        $confuserConfigFilePath = $confusedDir + "\" + $(Split-Path $inFile -leaf) + ".crproj"
        $finalConfuserConfig | Out-File -FilePath $confuserConfigFilePath

        
        Confuser.CLI.exe -n $confuserConfigFilePath | Out-Null

        if ($LastExitCode -ne 0)
        {
            Write-Host "[-] Confuser cli obfuscation failed" -ForegroundColor Red 
            Write-Host $output
            return
        }
        else{
            Write-Host "[+] Obfuscation successful: $confusedDir\$(Split-Path -Path $inFile -Leaf)" -ForegroundColor Green 
            Write-Host ""
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
        Write-Host "[+] Encrypted assembly written: $outFilePath"

        $shaManaged.Dispose()
        $aesManaged.Dispose()
    }

    # https://github.com/TheWover/donut
    Function donut ($donutArgs){
        Write-Host "[+] Uh, I'm just running donut at this point lol"
        donut.exe $donutArgs
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

    initCheck

    <# If jsonFile given, update the variables #>
    if($jsonFile){
        $jsonData = (Get-Content -Raw -Path $jsonFile | ConvertFrom-Json)
        $outDir = $jsonData.outDir 

        if(!(Test-Path -Path $jsonData.outDir)){
            Write-Host "[-] Path does not exist. Creating path."
            New-Item -Path $jsonData.outDir -ItemType "Directory"
        }
    }
    
    <# If no jsonFile and (no inFile, no slnPath, no OutDir), then use the default jsonFile #>
    # TODO: Implement. 

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
                    compile $slnPath $outDir $tool.arch $tool.outputType
                }
            }
        }

        # Compile all tools inside jsonFile 
        elseif ($jsonFile){
            foreach ($tool in $jsonData.tools) {
                $slnPath = Join-Path -Path $outDir -childPath $tool.slnPath
                compile $slnPath $outDir $tool.arch $tool.outputType
            }
        }

        # Compile specific tool the user wants 
        elseif(-not $jsonFile){
            compile $slnPath $outdir $arch $outputType
        }

        else{
            Write-Host "[-] Wrong parameter combination. Exiting." -ForegroundColor Red
            return 
        }
    }

    <# Obufscate #>
    if($obfuscate){
        try{
            # get all dll or exe files from outdir 
            $inFiles = (Get-ChildItem $outDir | Where-Object { ($_.Extension -eq ".dll") -or ($_.Extension -eq ".exe") }).Name
        }
        catch{
            Write-Host "[-] Cannot find any PE files in $outDir . Exiting." -ForegroundColor Red
            return 
        }

        # Obufscate specific tool inside jsonFile 
        if ($jsonFile -and $toolName){
            Write-Host "[+] Default confuserConfig = $confuserConfig"
            foreach ($inFile in $inFiles) {
                if( $inFile.ToLower().Contains( $toolName.ToLower())) {
                    if ($inFile.EndsWith('.dll') -or $inFile.EndsWith('.exe')){
                        $toolslnPath = $jsonData.tools | where{$_.Name -eq $toolName} | Select-Object -ExpandProperty slnPath
                        $finalToolslnPath = Join-Path -Path $outDir -ChildPath $toolslnPath
                        $inFile = Join-Path -Path $outDir -ChildPath $inFile
                        obfuscate $inFile $outDir $finalToolslnPath $confuserConfig $level 
                    }
                }
            }
        }

        # Obfuscate all tools inside jsonFile 
        elseif($jsonFile){
            Write-Host "[+] Default confuserConfig = $confuserConfig"
            foreach ($inFile in $inFiles) {
                foreach ($toolName in ($jsonData.tools.Name).ToLower()) {
                    if ($inFile.ToLower().Contains($toolName.ToLower())) {
                        $inFile = Join-Path -Path $outDir -ChildPath $inFile
                        $toolslnPath = $jsonData.tools | where{$_.Name -eq $toolName} | Select-Object -ExpandProperty slnPath
                        $finalToolslnPath = Join-Path -Path $outDir -ChildPath $toolslnPath
                        Write-Host "[+] Obfuscating $inFile" 
                        obfuscate $inFile $outDir $finalToolslnPath $confuserConfig $level 
                    }
                }
            }
        }

        # Obfuscate specific tool with filepath 
        elseif($inFile -and $outDir){
            obfuscate $inFile $outDir $confuserConfig $level 
        }

        else{
            Write-Host "[-] Wrong parameter combination. Exiting." -ForegroundColor Red
            return 
        }
    }

    <# Encrypt with AES256. #>
    if($encrypt){

        # Encrypt invidivual file  
        if ($inFile -and $key){
            Write-Host "[+] AES256 Encrypting $inFile with $key ..."
            aes256Encrypt $inFile $key
        }

        # Encrypt tools within jsonFile  
        elseif ($jsonFile -and $key) {
            $userAnswer = Read-Host "`n[+] Encrypt confused assemblies (confused)? Or compiled assemblies (compiled)?"

            if($userAnswer.ToLower() -eq "confused"){
                Write-Host "`n[+] Encrypting all .exe/.dll assemblies from $outDir\Confused ..."
                Write-Host "[+] Encrypting begins in 5 seconds"
                Start-Sleep -Seconds 5 
                $confusedDir = Join-Path -Path $outDir -ChildPath "Confused"
                $inFiles = (Get-ChildItem $confusedDir | Where-Object { ($_.Extension -eq ".dll") -or ($_.Extension -eq ".exe") }).Name
                foreach ($inFile in $inFiles) {
                    aes256Encrypt $inFile $key 
                }
            }

            elseif ($userAnswer.ToLower() -eq "compiled"){
                Write-Host "[+] Encrypting all .exe/.dll assmeblies from $outDir ..."
                Write-Host "[+] Encrypting begins in 5 seconds"
                Start-Sleep -Seconds 5 

                $inFiles = (Get-ChildItem $outDir | Where-Object { ($_.Extension -eq ".dll") -or ($_.Extension -eq ".exe") }).Name
                foreach ($inFile in $inFiles) {
                    aes256Encrypt $inFile $key 
                }
            }
        }

        else{
            Write-Host "[-] Wrong parameter combination. Either give me 'inFile' or 'jsonFile' with 'key'. " -ForegroundColor Red
            return 
        }
    }
}
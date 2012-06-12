$user = read-host -Prompt "Username: " 
$password = Read-Host -prompt "Password: " -asSecureString
$credential = new-object system.management.automation.PSCredential $user,$password

$strFilter = "computer"
 
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
 
$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
$objSearcher.SearchRoot = $objDomain
$objSearcher.SearchScope = "Subtree" 
$objSearcher.PageSize = 1000 

$objSearcher.Filter = "(objectCategory=$strFilter)"

$colResults = $objSearcher.FindAll()

[string]$query = 'Select * from Win32_Volume where DriveType = 3'

  if ($drive) {
    $query += " And DriveLetter LIKE '$drive%'"
  }


foreach ($i in $colResults) 
    {
        $objComputer = $i.GetDirectoryEntry()
		Write-Host "[*] Defragmentation started for" ($objComputer.Name)
		$volumes = (Get-WmiObject -Query $query -ComputerName $objComputer.Name -credential $credential)
	foreach ($volume in $volumes) {
		if ($volume.DriveLetter -eq $null){
		}
		else {
		Write-Host "Defragmenting" ($volume.DriveLetter)
		$a = ($volume.DriveLetter).Replace('`n|`t|`r',"")
		Get-WmiObject Win32_Volume -filter "DriveLetter='$a'" -computer $objComputer.Name -credential $credential | Invoke-WmiMethod -Name Defrag -ArgumentList @($false)
		}
		}
    }

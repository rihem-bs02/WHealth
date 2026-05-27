New-Item -ItemType Directory -Force -Path "models\malvisor" | Out-Null
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/PrathicaShettyM/MalVisor/main/server/analysis/malware_model.pkl" -OutFile "models\malvisor\malware_model.pkl"
Write-Host "Downloaded models\malvisor\malware_model.pkl"

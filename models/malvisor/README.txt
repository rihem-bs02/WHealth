Place the MalVisor LightGBM model here:

models/malvisor/malware_model.pkl

You can download it manually from:
https://github.com/PrathicaShettyM/MalVisor/blob/main/server/analysis/malware_model.pkl

PowerShell example from the project root:
mkdir models\malvisor -Force
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/PrathicaShettyM/MalVisor/main/server/analysis/malware_model.pkl" -OutFile "models\malvisor\malware_model.pkl"

Security note: loading .pkl files can execute code. Only use a model file from a source you trust.

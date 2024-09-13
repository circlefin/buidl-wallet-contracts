# Folder Structure

This folder contains logs of runs of the foundry scripts in the `script/` folder. The files are grouped as follows:
```
<FoundryScriptName>/<chain ID>/run-<Unix timestamp>.json

# Example: 001_DeployPluginManager.s.sol/11155111/run-1724875951.json
```

Each run will generate a file of the format `run-<Unix timestamp>.json`. In addition to this file, there will also be a `run-latest.json` file in each in each `<ScriptName>/<chain ID>/` folder keeping track of the last run. Note: this means that we will likely have two duplicate files in any `<ScriptName>/<chain ID>/` folder.

# Resources

- IDs of common chains: <https://chainlist.org/>
![Logo](https://raw.githubusercontent.com/rxfe-a/scp-ui/refs/heads/main/.github/repoitems/logo-full.png "Logo")

# SCP-UI (Secure Copy Protocol UI)
A simple UI Helper that makes it easier to use and understand the SCP protocol
> [!WARNING]  
> This repo is still in development and also a W.I.P so please be cautious while using this project

> [!NOTE]  
> This has only been tested on python on MacOS versions any other platform is currently unstable untill further notice

## ( 1 ) Compiling with python
- Make sure that you have the latest version of <b><a href="https://www.python.org/downloads/"> Python/Python3 </a></b> Installed onto your system path

- Clone the repository
```
git clone https://github.com/rxfe-a/scp-ui

cd scp-ui/Python
```
- Setup venv <b>RECOMMENDED</b>
```
python3 -m venv venv # name wtv you want
## For Linux/MacOS Below
source venv/bin/Activate
## For Windows
venv/Scripts/Activate
```
- Install dependecies including ```pyinstaller```
```
pip install -r requirements.txt pyinstaller
```
- COMPILEEEEE
```
pyinstaller --onefile --noconsole --icon="scp.ico" app.py
```
- Depending on your OS Configuration the build should be placed in a directory called /dist

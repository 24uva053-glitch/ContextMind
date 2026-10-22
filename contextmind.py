name: Build ContextMind

on:
  workflow_dispatch:

jobs:
  build:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.8"

      - name: Install PyInstaller
        run: pip install pyinstaller

      - name: Build EXE
        run: pyinstaller --noconsole --onefile --name ContextMind contextmind.py

      - uses: actions/upload-artifact@v4
        with:
          name: ContextMind-exe
          path: dist/ContextMind.exe

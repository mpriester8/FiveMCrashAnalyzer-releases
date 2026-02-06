' FiveM Crash Analyzer - Silent Launcher
' This script launches the analyzer GUI without showing any console windows

Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")

' Get the directory where this script is located
strScriptPath = objFSO.GetParentFolderName(WScript.ScriptFullName)

' Build path to analyzer.py
strAnalyzerPath = strScriptPath & "\crash_analyzer\analyzer.py"

' Try pythonw first (no console), fall back to python
On Error Resume Next
objShell.Run "pythonw """ & strAnalyzerPath & """", 0, False

If Err.Number <> 0 Then
    ' pythonw failed, try python
    Err.Clear
    objShell.Run "python """ & strAnalyzerPath & """", 0, False
End If

' Clean up
Set objShell = Nothing
Set objFSO = Nothing

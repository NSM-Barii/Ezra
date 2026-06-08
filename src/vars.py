# THIS WILL HOLD MODULE WIDE VARS


# UI IMPORTS
from rich.console import Console

from rich.panel import Panel
from rich.table import Table
import pyfiglet

# CONSTANTS
console = Console()



class Variables():
    """Multi - Vars"""


    console = console
    table   = Table(title="LAN Devices", style="bold red", border_style="bold purple", header_style="bold red")
    table.add_column("")
    devices = {}
    num     = 0
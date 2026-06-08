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
    panel   = Panel(renderable="Developed by NSM Barii", style="bord red", border_style="bold purple", expand=False, title="Stats")
    table   = Table(title="LAN Devices", style="bold red", border_style="bold purple", header_style="bold red")
    
    ip_srcs = []
    devices = {}
    dev_apples  = 0
    dev_roku    = 0
    dev_google  = 0
    dev_amazon  = 0
    dev_samsung = 0
    dev_unknown = 0
    dev_total   = 0
    pkts        = 0
